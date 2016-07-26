#include <fcntl.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>

#include <gsscon.h>
#include <tr_rp.h>
#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <trp_ptable.h>
#include <trp_rtable.h>
#include <tr_debug.h>


static int trps_destructor(void *object)
{
  TRPS_INSTANCE *trps=talloc_get_type_abort(object, TRPS_INSTANCE);
  if (trps->rtable!=NULL)
    trp_rtable_free(trps->rtable);
  return 0;
}

TRPS_INSTANCE *trps_new (TALLOC_CTX *mem_ctx)
{
  TRPS_INSTANCE *trps=talloc(mem_ctx, TRPS_INSTANCE);
  if (trps!=NULL)  {
    trps->hostname=NULL;
    trps->port=0;
    trps->cookie=NULL;
    trps->conn=NULL;
    trps->trpc=NULL;
    trps->update_interval=(struct timeval){0,0};
    trps->sweep_interval=(struct timeval){0,0};

    trps->mq=tr_mq_new(trps);
    if (trps->mq==NULL) {
      /* failed to allocate mq */
      talloc_free(trps);
      return NULL;
    }

    trps->ptable=trp_ptable_new(trps);
    if (trps->ptable==NULL) {
      /* failed to allocate ptable */
      talloc_free(trps);
      return NULL;
    }

    trps->rtable=NULL;
    if (trps_init_rtable(trps) != TRP_SUCCESS) {
      /* failed to allocate rtable */
      talloc_free(trps);
      return NULL;
    }

    talloc_set_destructor((void *)trps, trps_destructor);
  }
  return trps;
}

/* create a new route table, first discarding an old one if necessary */
TRP_RC trps_init_rtable(TRPS_INSTANCE *trps)
{
  if (trps->rtable != NULL) {
    trp_rtable_free(trps->rtable);
    trps->rtable=NULL;
  }

  trps->rtable=trp_rtable_new();
  if (trps->rtable==NULL) {
    return TRP_NOMEM;
  }
  return TRP_SUCCESS;
}

void trps_clear_rtable(TRPS_INSTANCE *trps)
{
  trp_rtable_clear(trps->rtable);
}

void trps_free (TRPS_INSTANCE *trps)
{
  if (trps!=NULL)
    talloc_free(trps);
}

TR_MQ_MSG *trps_mq_pop(TRPS_INSTANCE *trps)
{
  return tr_mq_pop(trps->mq);
}

void trps_mq_append(TRPS_INSTANCE *trps, TR_MQ_MSG *msg)
{
  tr_mq_append(trps->mq, msg);
}

unsigned int trps_get_connect_interval(TRPS_INSTANCE *trps)
{
  return trps->connect_interval.tv_sec;
}

void trps_set_connect_interval(TRPS_INSTANCE *trps, unsigned int interval)
{
  trps->connect_interval.tv_sec=interval;
  trps->connect_interval.tv_usec=0;
}

unsigned int trps_get_update_interval(TRPS_INSTANCE *trps)
{
  return trps->update_interval.tv_sec;
}

void trps_set_update_interval(TRPS_INSTANCE *trps, unsigned int interval)
{
  trps->update_interval.tv_sec=interval;
  trps->update_interval.tv_usec=0;
}

unsigned int trps_get_sweep_interval(TRPS_INSTANCE *trps)
{
  return trps->sweep_interval.tv_sec;
}

void trps_set_sweep_interval(TRPS_INSTANCE *trps, unsigned int interval)
{
  trps->sweep_interval.tv_sec=interval;
  trps->sweep_interval.tv_usec=0;
}

TRPC_INSTANCE *trps_find_trpc(TRPS_INSTANCE *trps, TRP_PEER *peer)
{
  TRPC_INSTANCE *cur=NULL;
  TR_NAME *name=NULL;
  TR_NAME *peer_gssname=trp_peer_get_gssname(peer);

  for (cur=trps->trpc; cur!=NULL; cur=trpc_get_next(cur)) {
    name=trpc_get_gssname(cur);
    if ((name!=NULL) && (0==tr_name_cmp(peer_gssname, name))) {
      break;
    }
  }
  tr_free_name(peer_gssname);
  return cur;
}

void trps_add_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *new)
{
  if (trps->conn==NULL)
    trps->conn=new;
  else
    trp_connection_append(trps->conn, new);

  talloc_steal(trps, new);
}

/* ok to call more than once; guarantees connection no longer in the list.
 * Caller is responsible for freeing the removed element afterwards.  */
void trps_remove_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *remove)
{
  trps->conn=trp_connection_remove(trps->conn, remove);
}

void trps_add_trpc(TRPS_INSTANCE *trps, TRPC_INSTANCE *trpc)
{
  if (trps->trpc==NULL)
    trps->trpc=trpc;
  else
    trpc_append(trps->trpc, trpc);

  talloc_steal(trps, trpc);
}

/* ok to call more than once; guarantees trpc no longer in the list.
 * Caller is responsible for freeing the removed element afterwards.  */
void trps_remove_trpc(TRPS_INSTANCE *trps, TRPC_INSTANCE *remove)
{
  trps->trpc=trpc_remove(trps->trpc, remove);
}

TRP_RC trps_send_msg(TRPS_INSTANCE *trps, TRP_PEER *peer, const char *msg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_MQ_MSG *mq_msg=NULL;
  char *msg_dup=NULL;
  TRP_RC rc=TRP_ERROR;
  TRPC_INSTANCE *trpc=NULL;

  /* get the connection for this peer */
  trpc=trps_find_trpc(trps, peer);
  if ((trpc==NULL) || (trpc_get_status(trps->trpc)!=TRP_CONNECTION_UP)) {
    /* We could just let these sit on the queue in the hopes that a connection
     * is eventually established. However, we'd then have to ensure the queue
     * didn't keep growing, etc. */
    tr_warning("trps_send_msg: skipping message queued while TRPC connection not up.");
  } else {
    mq_msg=tr_mq_msg_new(tmp_ctx, TR_MQMSG_TRPC_SEND);
    msg_dup=talloc_strdup(mq_msg, msg); /* get local copy in mq_msg context */
    tr_mq_msg_set_payload(mq_msg, msg_dup, NULL); /* no need for a free() func */
    trpc_mq_append(trpc, mq_msg);
    rc=TRP_SUCCESS;
  }
  talloc_free(tmp_ctx);
  return rc;
}

static int trps_listen (TRPS_INSTANCE *trps, int port) 
{
  int rc = 0;
  int conn = -1;
  int optval = 1;

  union {
    struct sockaddr_storage storage;
    struct sockaddr_in in4;
  } addr;

  struct sockaddr_in *saddr = (struct sockaddr_in *) &addr.in4;

  saddr->sin_port = htons (port);
  saddr->sin_family = AF_INET;
  saddr->sin_addr.s_addr = INADDR_ANY;

  if (0 > (conn = socket (AF_INET, SOCK_STREAM, 0)))
    return conn;

  setsockopt(conn, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  if (0 > (rc = bind (conn, (struct sockaddr *) saddr, sizeof(struct sockaddr_in))))
    return rc;

  if (0 > (rc = listen(conn, 512)))
    return rc;

  tr_debug("trps_listen: TRP Server listening on port %d", port);
  return conn;
}

#if 0 /* remove this if I forget to do so */
/* returns EACCES if authorization is denied */
int trps_auth_cb(gss_name_t clientName, gss_buffer_t displayName, void *data)
{
  TRPS_INSTANCE *trps = (TRPS_INSTANCE *)data;
  int result=0;

  if (0!=trps->auth_handler(clientName, displayName, trps->cookie)) {
    tr_debug("trps_auth_cb: client '%.*s' denied authorization.", displayName->length, displayName->value);
    result=EACCES; /* denied */
  }

  return result;
}
#endif 

/* get the currently selected route if available */
TRP_RENTRY *trps_get_route(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer)
{
  return trp_rtable_get_entry(trps->rtable, comm, realm, peer);
}

TRP_RENTRY *trps_get_selected_route(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm)
{
  return trp_rtable_get_selected_entry(trps->rtable, comm, realm);
}

/* copy the result if you want to keep it */
TR_NAME *trps_get_next_hop(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm)
{
  TRP_RENTRY *route=trps_get_selected_route(trps, comm, realm);
  if (route==NULL)
    return NULL;

  return trp_rentry_get_next_hop(route);
}


/* mark a route as retracted */
static void trps_retract_route(TRPS_INSTANCE *trps, TRP_RENTRY *entry)
{
  trp_rentry_set_metric(entry, TRP_METRIC_INFINITY);
}

/* is this route retracted? */
static int trps_route_retracted(TRPS_INSTANCE *trps, TRP_RENTRY *entry)
{
  return (trp_metric_is_infinite(trp_rentry_get_metric(entry)));
}

static TRP_RC trps_read_message(TRPS_INSTANCE *trps, TRP_CONNECTION *conn, TR_MSG **msg)
{
  int err=0;
  char *buf=NULL;
  size_t buflen = 0;
  TR_NAME *peer=NULL;

  tr_debug("trps_read_message: started");
  if (err = gsscon_read_encrypted_token(trp_connection_get_fd(conn),
                                       *(trp_connection_get_gssctx(conn)), 
                                       &buf,
                                       &buflen)) {
    tr_debug("trps_read_message: error");
    if (buf)
      free(buf);
    return TRP_ERROR;
  }

  tr_debug("trps_read_message(): Request Received, %u bytes.", (unsigned) buflen);
  tr_debug("trps_read_message(): %.*s", buflen, buf);

  *msg=tr_msg_decode(buf, buflen);
  free(buf);
  if (*msg==NULL)
    return TRP_NOPARSE;

  peer=trp_connection_get_peer(conn);
  /* verify we received a message we support, otherwise drop it now */
  switch (tr_msg_get_msg_type(*msg)) {
  case TRP_UPDATE:
    trp_upd_set_peer(tr_msg_get_trp_upd(*msg), tr_dup_name(peer));
    break;

  case TRP_REQUEST:
    trp_req_set_peer(tr_msg_get_trp_req(*msg), tr_dup_name(peer));
    break;

  default:
    tr_debug("trps_read_message: received unsupported message from %.*s", peer->len, peer->buf);
    tr_msg_free_decoded(*msg);
    *msg=NULL;
    return TRP_UNSUPPORTED;
  }
  
  return TRP_SUCCESS;
}

int trps_get_listener(TRPS_INSTANCE *trps,
                      TRPS_MSG_FUNC msg_handler,
                      TRP_AUTH_FUNC auth_handler,
                      const char *hostname,
                      unsigned int port,
                      void *cookie)
{
  int listen = -1;

  if (0 > (listen = trps_listen(trps, port))) {
    char errbuf[256];
    if (0 == strerror_r(errno, errbuf, 256)) {
      tr_debug("trps_get_listener: Error opening port %d: %s.", port, errbuf);
    } else {
      tr_debug("trps_get_listener: Unknown error openining port %d.", port);
    }
  } 

  if (listen > 0) {
    /* opening port succeeded */
    tr_debug("trps_get_listener: Opened port %d.", port);
    
    /* make this socket non-blocking */
    if (0 != fcntl(listen, F_SETFL, O_NONBLOCK)) {
      tr_debug("trps_get_listener: Error setting O_NONBLOCK.");
      close(listen);
      listen=-1;
    }
  }

  if (listen > 0) {
    /* store the caller's request handler & cookie */
    trps->msg_handler = msg_handler;
    trps->auth_handler = auth_handler;
    trps->hostname = talloc_strdup(trps, hostname);
    trps->port = port;
    trps->cookie = cookie;
  }

  return listen;
}

void trps_handle_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *conn)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_MSG *msg=NULL;
  TRP_RC rc=TRP_ERROR;

  /* try to establish a GSS context */
  if (0!=trp_connection_auth(conn, trps->auth_handler, trps->cookie)) {
    tr_notice("tr_trps_conn_thread: failed to authorize connection");
    pthread_exit(NULL);
  }
  tr_notice("trps_handle_connection: authorized connection");
  
  /* loop as long as the connection exists */
  while (trp_connection_get_status(conn)==TRP_CONNECTION_UP) {
    rc=trps_read_message(trps, conn, &msg);
    switch(rc) {
    case TRP_SUCCESS:
      trps->msg_handler(trps, conn, msg); /* send the TR_MSG off to the callback */
      break;

    case TRP_ERROR:
      trp_connection_close(conn);
      break;

    default:
      tr_debug("trps_handle_connection: trps_read_message failed (%d)", rc);
    }
  }

  tr_debug("trps_handle_connection: connection closed.");
  talloc_free(tmp_ctx);
}

static TRP_RC trps_validate_update(TRPS_INSTANCE *trps, TRP_UPD *upd)
{
  if (trp_upd_get_inforec(upd)==NULL) {
    tr_notice("trps_validate_update: received TRP update with no info records.");
    return TRP_ERROR;
  }

  if (trp_upd_get_peer(upd)==NULL) {
    tr_notice("trps_validate_update: received TRP update without origin peer information.");
    return TRP_ERROR;
  }
  
  return TRP_SUCCESS;
}

/* ensure that the update could be accepted if feasible */
static TRP_RC trps_validate_inforec(TRPS_INSTANCE *trps, TRP_INFOREC *rec)
{
  switch(trp_inforec_get_type(rec)) {
  case TRP_INFOREC_TYPE_ROUTE:
    if ((trp_inforec_get_comm(rec)==NULL)
       || (trp_inforec_get_realm(rec)==NULL)
       || (trp_inforec_get_trust_router(rec)==NULL)
       || (trp_inforec_get_next_hop(rec)==NULL)) {
      tr_debug("trps_validate_inforec: missing record info.");
      return TRP_ERROR;
    }

    /* check for valid metric */
    if (trp_metric_is_invalid(trp_inforec_get_metric(rec))) {
      tr_debug("trps_validate_inforec: invalid metric (%u).", trp_inforec_get_metric(rec));
      return TRP_ERROR;
    }

    /* check for valid interval */
    if (trp_inforec_get_interval(rec)==TRP_INTERVAL_INVALID) {
      tr_debug("trps_validate_inforec: invalid interval.");
      return TRP_ERROR;
    }
    break;

  default:
    tr_notice("trps_validate_inforec: unsupported record type.");
    return TRP_UNSUPPORTED;
  }

  return TRP_SUCCESS;
}

/* link cost to a peer */
static unsigned int trps_cost(TRPS_INSTANCE *trps, TR_NAME *peer)
{
  return 1;
}

static unsigned int trps_advertised_metric(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer)
{
  TRP_RENTRY *entry=trp_rtable_get_entry(trps->rtable, comm, realm, peer);
  if (entry==NULL)
    return TRP_METRIC_INFINITY;
  return trp_rentry_get_metric(entry) + trps_cost(trps, peer);
}

static int trps_check_feasibility(TRPS_INSTANCE *trps, TRP_INFOREC *rec)
{
  unsigned int rec_metric=trp_inforec_get_metric(rec);
  unsigned int new_metric=0;
  unsigned int current_metric=0;
  TR_NAME *next_hop=NULL;

  /* we check these in the validation stage, but just in case... */
  if (trp_metric_is_invalid(rec_metric))
    return 0;

  /* retractions (aka infinite metrics) are always feasible */
  if (trp_metric_is_infinite(rec_metric))
    return 1;

  /* updates from our current next hop are always feasible*/
  next_hop=trps_get_next_hop(trps,
                             trp_inforec_get_comm(rec),
                             trp_inforec_get_realm(rec));;
  if ((next_hop!=NULL)
     && (0==tr_name_cmp(next_hop,trp_inforec_get_next_hop(rec)))) {
    return 1;
  }
    

  /* compare the existing metric we advertise to what we would advertise
   * if we accept this update */
  current_metric=trps_advertised_metric(trps,
                                        trp_inforec_get_comm(rec),
                                        trp_inforec_get_realm(rec),
                                        trp_inforec_get_next_hop(rec));
  new_metric=rec_metric + trps_cost(trps, trp_inforec_get_next_hop(rec));
  if (new_metric <= current_metric)
    return 1;
  else
    return 0;
}

/* uses memory pointed to by *ts, also returns that value. On error, its contents are {0,0} */
static struct timespec *trps_compute_expiry(TRPS_INSTANCE *trps, unsigned int interval, struct timespec *ts)
{
  const unsigned int small_factor=3; /* how many intervals we wait before expiring */
  if (0!=clock_gettime(CLOCK_REALTIME, ts)) {
    tr_err("trps_compute_expiry: could not read realtime clock.");
    ts->tv_sec=0;
    ts->tv_nsec=0;
  }
  ts->tv_sec += small_factor*interval;
  return ts;
}

static TRP_RC trps_accept_update(TRPS_INSTANCE *trps, TRP_INFOREC *rec)
{
  TRP_RENTRY *entry=NULL;

  entry=trp_rtable_get_entry(trps->rtable,
                             trp_inforec_get_comm(rec),
                             trp_inforec_get_realm(rec),
                             trp_inforec_get_next_hop(rec));
  if (entry==NULL) {
    entry=trp_rentry_new(NULL);
    if (entry==NULL) {
      tr_err("trps_accept_update: unable to allocate new entry.");
      return TRP_NOMEM;
    }

    trp_rentry_set_apc(entry, tr_dup_name(trp_inforec_get_comm(rec)));
    trp_rentry_set_realm(entry, tr_dup_name(trp_inforec_get_realm(rec)));
    trp_rentry_set_peer(entry, tr_dup_name(trp_inforec_get_next_hop(rec)));
    trp_rentry_set_trust_router(entry, tr_dup_name(trp_inforec_get_trust_router(rec)));
    trp_rentry_set_next_hop(entry, tr_dup_name(trp_inforec_get_next_hop(rec)));
    if ((trp_rentry_get_apc(entry)==NULL)
       ||(trp_rentry_get_realm(entry)==NULL)
       ||(trp_rentry_get_peer(entry)==NULL)
       ||(trp_rentry_get_trust_router(entry)==NULL)
       ||(trp_rentry_get_next_hop(entry)==NULL)) {
      /* at least one field could not be allocated */
      tr_err("trps_accept_update: unable to allocate all fields for entry.");
      trp_rentry_free(entry);
      return TRP_NOMEM;
    }
    trp_rtable_add(trps->rtable, entry);
  }

  /* We now have an entry in the table, whether it's new or not. Update metric and expiry, unless
   * the metric is infinity. An infinite metric can only occur here if we just retracted an existing
   * route (we never accept retractions as new routes), so there is no risk of leaving the expiry
   * time unset on a new route entry. */
  tr_debug("trps_accept_update: accepting route update.");
  trp_rentry_set_metric(entry, trp_inforec_get_metric(rec));
  trp_rentry_set_interval(entry, trp_inforec_get_interval(rec));
  if (!trps_route_retracted(trps, entry)) {
    tr_debug("trps_accept_update: route not retracted, setting expiry timer.");
    trp_rentry_set_expiry(entry, trps_compute_expiry(trps,
                                                     trp_rentry_get_interval(entry),
                                                     trp_rentry_get_expiry(entry)));
  }
  return TRP_SUCCESS;
}

/* TODO: handle community updates */
static TRP_RC trps_handle_update(TRPS_INSTANCE *trps, TRP_UPD *upd)
{
  unsigned int feas=0;
  TRP_INFOREC *rec=NULL;
  TRP_RENTRY *route=NULL;

  if (trps_validate_update(trps, upd) != TRP_SUCCESS) {
    tr_notice("trps_handle_update: received invalid TRP update.");
    return TRP_ERROR;
  }

  rec=trp_upd_get_inforec(upd);
  for (;rec!=NULL; rec=trp_inforec_get_next(rec)) {
    /* validate/sanity check the record update */
    if (trps_validate_inforec(trps, rec) != TRP_SUCCESS) {
      tr_notice("trps_handle_update: invalid record in TRP update.");
      continue;
    }

    /* determine feasibility */
    feas=trps_check_feasibility(trps, rec);
    tr_debug("trps_handle_update: record feasibility=%d", feas);

    /* do we have an existing route? */
    route=trps_get_route(trps, trp_inforec_get_comm(rec), trp_inforec_get_realm(rec), trp_inforec_get_next_hop(rec));
    if (route!=NULL) {
      /* there was a route table entry already */
      tr_debug("trps_handle_updates: route entry already exists.");
      if (feas) {
        /* Update is feasible. Accept it. */
        trps_accept_update(trps, rec);
      } else {
        /* Update is infeasible. Ignore it unless the trust router has changed. */
        if (0!=tr_name_cmp(trp_rentry_get_trust_router(route),
                           trp_inforec_get_trust_router(rec))) {
          /* the trust router associated with the route has changed, treat update as a retraction */
          trps_retract_route(trps, route);
        }
      }
    } else {
      /* No existing route table entry. Ignore it unless it is feasible and not a retraction. */
      tr_debug("trps_handle_update: no route entry exists yet.");
      if (feas && trp_metric_is_finite(trp_inforec_get_metric(rec)))
        trps_accept_update(trps, rec);
    }
  }
  return TRP_SUCCESS;
}

/* choose the best route to comm/realm, optionally excluding routes to a particular peer */
static TRP_RENTRY *trps_find_best_route(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm, TR_NAME *exclude_peer)
{
  TRP_RENTRY **entry=NULL;
  TRP_RENTRY *best=NULL;
  size_t n_entry=0;
  unsigned int kk=0;
  unsigned int kk_min=0;
  unsigned int min_metric=TRP_METRIC_INFINITY;

  entry=trp_rtable_get_realm_entries(trps->rtable, comm, realm, &n_entry);
  for (kk=0; kk<n_entry; kk++) {
    if (trp_rentry_get_metric(entry[kk]) < min_metric) {
      if ((exclude_peer==NULL) || (0!=tr_name_cmp(trp_rentry_get_peer(entry[kk]),
                                                  exclude_peer))) {
        kk_min=kk;
        min_metric=trp_rentry_get_metric(entry[kk]);
      }
    }
  }
  if (trp_metric_is_finite(min_metric));
    best=entry[kk_min];
  
  talloc_free(entry);
  return best;
}

/* TODO: think this through more carefully. At least ought to add hysteresis
 * to avoid flapping between routers or routes. */
TRP_RC trps_update_active_routes(TRPS_INSTANCE *trps)
{
  size_t n_apc=0, ii=0;
  TR_NAME **apc=trp_rtable_get_apcs(trps->rtable, &n_apc);
  size_t n_realm=0, jj=0;
  TR_NAME **realm=NULL;
  TRP_RENTRY *best_route=NULL, *cur_route=NULL;
  unsigned int best_metric=0, cur_metric=0;

  for (ii=0; ii<n_apc; ii++) {
    realm=trp_rtable_get_apc_realms(trps->rtable, apc[ii], &n_realm);
    for (jj=0; jj<n_realm; jj++) {
      best_route=trps_find_best_route(trps, apc[ii], realm[jj], NULL);
      if (best_route==NULL)
        best_metric=TRP_METRIC_INFINITY;
      else
        best_metric=trp_rentry_get_metric(best_route);

      cur_route=trps_get_selected_route(trps, apc[ii], realm[jj]);
      if (cur_route!=NULL) {
        cur_metric=trp_rentry_get_metric(cur_route);
        if ((best_metric < cur_metric) && (trp_metric_is_finite(best_metric))) {
          trp_rentry_set_selected(cur_route, 0);
          trp_rentry_set_selected(best_route, 1);
        } else if (!trp_metric_is_finite(cur_metric)) /* rejects infinite or invalid metrics */
          trp_rentry_set_selected(cur_route, 0);
      } else if (trp_metric_is_finite(best_metric))
        trp_rentry_set_selected(best_route, 1);
    }
    if (realm!=NULL)
      talloc_free(realm);
    realm=NULL; n_realm=0;
  }
  if (apc!=NULL)
    talloc_free(apc);
  apc=NULL; n_apc=0;

  return TRP_SUCCESS;
}

TRP_RC trps_handle_tr_msg(TRPS_INSTANCE *trps, TR_MSG *tr_msg)
{
  TRP_RC rc=TRP_ERROR;

  switch (tr_msg_get_msg_type(tr_msg)) {
  case TRP_UPDATE:
    rc=trps_handle_update(trps, tr_msg_get_trp_upd(tr_msg));
    if (rc==TRP_SUCCESS) {
      rc=trps_update_active_routes(trps);
    }
    return rc;

  case TRP_REQUEST:
    return TRP_UNSUPPORTED;

  default:
    /* unknown error or one we don't care about (e.g., TID messages) */
    return TRP_ERROR;
  }
}

/* true if curtime >= expiry */
static int trps_expired(struct timespec *expiry, struct timespec *curtime)
{
  return ((curtime->tv_sec > expiry->tv_sec)
         || ((curtime->tv_sec == expiry->tv_sec)
            &&(curtime->tv_nsec > expiry->tv_nsec)));
}

/* Sweep for expired routes. For each expired route, if its metric is infinite, the route is flushed.
 * If its metric is finite, the metric is set to infinite and the route's expiration time is updated. */
TRP_RC trps_sweep_routes(TRPS_INSTANCE *trps)
{
  struct timespec sweep_time={0,0};
  TRP_RENTRY **entry=NULL;
  size_t n_entry=0;
  size_t ii=0;

  /* use a single time for the entire sweep */
  if (0!=clock_gettime(CLOCK_REALTIME, &sweep_time)) {
    tr_err("trps_sweep_routes: could not read realtime clock.");
    sweep_time.tv_sec=0;
    sweep_time.tv_nsec=0;
    return TRP_ERROR;
  }

  entry=trp_rtable_get_entries(trps->rtable, &n_entry); /* must talloc_free *entry */

  /* loop over the entries */
  for (ii=0; ii<n_entry; ii++) {
    if (trps_expired(trp_rentry_get_expiry(entry[ii]), &sweep_time)) {
      tr_debug("trps_sweep_routes: route expired.");
      if (!trp_metric_is_finite(trp_rentry_get_metric(entry[ii]))) {
        /* flush route */
        tr_debug("trps_sweep_routes: metric was infinity, flushing route.");
        trp_rtable_remove(trps->rtable, entry[ii]); /* entry[ii] is no longer valid */
        entry[ii]=NULL;
      } else {
        /* set metric to infinity and reset timer */
        tr_debug("trps_sweep_routes: setting metric to infinity and resetting expiry.");
        trp_rentry_set_metric(entry[ii], TRP_METRIC_INFINITY);
        trp_rentry_set_expiry(entry[ii], trps_compute_expiry(trps,
                                                             trp_rentry_get_interval(entry[ii]),
                                                             trp_rentry_get_expiry(entry[ii])));
      }
    }
  }

  talloc_free(entry);
  return TRP_SUCCESS;
}

/* select the correct route to comm/realm to be announced to peer */
static TRP_RENTRY *trps_select_realm_update(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer_gssname)
{
  TRP_RENTRY *route;

  /* Take the currently selected route unless it is through the peer we're sending the update to.
   * I.e., enforce the split horizon rule. */
  route=trp_rtable_get_selected_entry(trps->rtable, comm, realm);
  if (route==NULL) {
    /* No selected route, this should only happen if the only route has been retracted,
     * in which case we do not want to advertise it. */
    return NULL;
  }
  if (0==tr_name_cmp(peer_gssname, trp_rentry_get_peer(route))) {
    /* the selected entry goes through the peer we're reporting to, choose an alternate */
    route=trps_find_best_route(trps, comm, realm, peer_gssname);
    if ((route==NULL) || (!trp_metric_is_finite(trp_rentry_get_metric(route))))
      route=NULL; /* don't advertise a nonexistent or retracted route */
  }
  return route;
}

/* returns an array of pointers to updates (*not* an array of updates). Returns number of entries
 * via n_update parameter. (The allocated space will generally be larger than required, see note in
 * the code.) */
static TRP_RENTRY **trps_select_updates_for_peer(TALLOC_CTX *memctx, TRPS_INSTANCE *trps, TR_NAME *peer_gssname, size_t *n_update)
{
  size_t n_apc=0;
  TR_NAME **apc=trp_rtable_get_apcs(trps->rtable, &n_apc);
  TR_NAME **realm=NULL;
  size_t n_realm=0;
  size_t ii=0, jj=0;
  TRP_RENTRY *best=NULL;
  TRP_RENTRY **result=NULL;
  size_t n_used=0;

  /* Need to allocate space for the results. For simplicity, we just allocate a block
   * with space for every route table entry to be returned. This is guaranteed to be large
   * enough. If the routing table gets very large, this may be wasteful, but that seems
   * unlikely to be significant in the near future. */
  result=talloc_array(memctx, TRP_RENTRY *, trp_rtable_size(trps->rtable));
  if (result==NULL) {
    talloc_free(apc);
    *n_update=0;
    return NULL;
  }
  
  for (ii=0; ii<n_apc; ii++) {
    realm=trp_rtable_get_apc_realms(trps->rtable, apc[ii], &n_realm);
    for (jj=0; jj<n_realm; jj++) {
      best=trps_select_realm_update(trps, apc[ii], realm[jj], peer_gssname);
      if (best!=NULL)
        result[n_used++]=best;
    }
    if (realm!=NULL)
      talloc_free(realm);
    realm=NULL;
    n_realm=0;
  }
  if (apc!=NULL)
    talloc_free(apc);

  *n_update=n_used;
  return result;
}

/* convert an rentry into a new trp update info record */
static TRP_INFOREC *trps_rentry_to_inforec(TALLOC_CTX *mem_ctx, TRPS_INSTANCE *trps, TRP_RENTRY *entry)
{
  TRP_INFOREC *rec=trp_inforec_new(mem_ctx, TRP_INFOREC_TYPE_ROUTE);
  unsigned int linkcost=0;

  if (rec!=NULL) {
    linkcost=trp_peer_get_linkcost(trps_get_peer(trps,
                                                 trp_rentry_get_next_hop(entry)));

    /* Note that we leave the next hop empty since the recipient fills that in.
     * This is where we add the link cost (currently always 1) to the next peer. */
    if ((trp_inforec_set_comm(rec, trp_rentry_dup_apc(entry)) != TRP_SUCCESS)
       ||(trp_inforec_set_realm(rec, trp_rentry_dup_realm(entry)) != TRP_SUCCESS)
       ||(trp_inforec_set_trust_router(rec, trp_rentry_dup_trust_router(entry)) != TRP_SUCCESS)
       ||(trp_inforec_set_metric(rec, trp_rentry_get_metric(entry)+linkcost) != TRP_SUCCESS)
       ||(trp_inforec_set_interval(rec, trps_get_update_interval(trps)) != TRP_SUCCESS)) {
      tr_err("trps_rentry_to_inforec: error creating route update.");
      talloc_free(rec);
      rec=NULL;
    }
  }
  return rec;
}

TRP_RC trps_scheduled_update(TRPS_INSTANCE *trps)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_PTABLE_ITER *iter=trp_ptable_iter_new(tmp_ctx);
  TRP_PEER *peer=NULL;
  TR_MSG msg; /* not a pointer! */
  TRP_UPD *upd=NULL;
  TRP_RENTRY **update_list=NULL;
  TRP_INFOREC *rec=NULL;
  size_t n_updates=0, ii=0;
  char *encoded=NULL;
  TRP_RC rc=TRP_ERROR;
  TR_NAME *peer_gssname=NULL;

  if (iter==NULL) {
    tr_err("trps_scheduled_update: failed to allocate peer table iterator.");
    talloc_free(tmp_ctx);
    return TRP_NOMEM;
  }

  for (peer=trp_ptable_iter_first(iter, trps->ptable);
       peer!=NULL;
       peer=trp_ptable_iter_next(iter))
  {
    peer_gssname=trp_peer_get_gssname(peer);
    tr_debug("trps_scheduled_update: preparing scheduled route update for %.*s",
             peer_gssname->len, peer_gssname->buf);
    /* do not fill in peer, recipient does that */
    update_list=trps_select_updates_for_peer(tmp_ctx, trps, peer_gssname, &n_updates);
    tr_free_name(peer_gssname); peer_gssname=NULL;
    if ((n_updates>0) && (update_list!=NULL)) {
      tr_debug("trps_scheduled_update: sending %u update records.", (unsigned int)n_updates);
      upd=trp_upd_new(tmp_ctx);

      for (ii=0; ii<n_updates; ii++) {
        rec=trps_rentry_to_inforec(tmp_ctx, trps, update_list[ii]);
        if (rec==NULL) {
          tr_err("trps_scheduled_update: could not create all update records.");
          rc=TRP_ERROR;
          goto cleanup;
        }
        trp_upd_add_inforec(upd, rec);
      }
      talloc_free(update_list);
      update_list=NULL;

      /* now encode the update message */
      tr_msg_set_trp_upd(&msg, upd);
      encoded=tr_msg_encode(&msg);
      if (encoded==NULL) {
        tr_err("trps_scheduled_update: error encoding update.");
        rc=TRP_ERROR;
        goto cleanup;
      }

      tr_debug("trps_scheduled_update: adding message to queue.");
      if (trps_send_msg(trps, peer, encoded) != TRP_SUCCESS)
        tr_err("trps_scheduled_update: error queueing update.");
      else
        tr_debug("trps_scheduled_update: update queued successfully.");

      encoded=NULL;
      tr_msg_free_encoded(encoded);
      trp_upd_free(upd);
      upd=NULL;
    }
  }
  
cleanup:
  trp_ptable_iter_free(iter);
  talloc_free(tmp_ctx);
  return rc;
}        

TRP_RC trps_add_route(TRPS_INSTANCE *trps, TRP_RENTRY *route)
{
  trp_rtable_add(trps->rtable, route); /* should return status */
  return TRP_SUCCESS; 
}

TRP_RC trps_add_peer(TRPS_INSTANCE *trps, TRP_PEER *peer)
{
  return trp_ptable_add(trps->ptable, peer);
}

TRP_PEER *trps_get_peer(TRPS_INSTANCE *trps, TR_NAME *gssname)
{
  return trp_ptable_find(trps->ptable, gssname);
}
