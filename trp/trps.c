#include <fcntl.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>

#include <gsscon.h>
#include <tr_rp.h>
#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <tr_gss.h>
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
    trps->ptable=NULL;

    trps->mq=tr_mq_new(trps);
    if (trps->mq==NULL) {
      /* failed to allocate mq */
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

void trps_mq_add(TRPS_INSTANCE *trps, TR_MQ_MSG *msg)
{
  tr_mq_add(trps->mq, msg);
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

void trps_set_ptable(TRPS_INSTANCE *trps, TRP_PTABLE *ptable)
{
  if (trps->ptable!=NULL)
    trp_ptable_free(trps->ptable);
  trps->ptable=ptable;
}

TRPC_INSTANCE *trps_find_trpc(TRPS_INSTANCE *trps, TRP_PEER *peer)
{
  TRPC_INSTANCE *cur=NULL;
  TR_NAME *name=NULL;
  TR_NAME *peer_servicename=trp_peer_get_servicename(peer);

  for (cur=trps->trpc; cur!=NULL; cur=trpc_get_next(cur)) {
    name=trpc_get_gssname(cur);
    if ((name!=NULL) && (0==tr_name_cmp(peer_servicename, name))) {
      break;
    }
  }
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
  /* instead, let's let that happen and then clear the queue when an attempt to
   * connect fails */
  if (trpc==NULL) {
    tr_warning("trps_send_msg: skipping message queued for missing TRP client entry.");
  } else {
    mq_msg=tr_mq_msg_new(tmp_ctx, TR_MQMSG_TRPC_SEND, TR_MQ_PRIO_NORMAL);
    msg_dup=talloc_strdup(mq_msg, msg); /* get local copy in mq_msg context */
    tr_mq_msg_set_payload(mq_msg, msg_dup, NULL); /* no need for a free() func */
    trpc_mq_add(trpc, mq_msg);
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

/* get the currently selected route if available */
TRP_ROUTE *trps_get_route(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer)
{
  return trp_rtable_get_entry(trps->rtable, comm, realm, peer);
}

TRP_ROUTE *trps_get_selected_route(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm)
{
  return trp_rtable_get_selected_entry(trps->rtable, comm, realm);
}

/* copy the result if you want to keep it */
TR_NAME *trps_get_next_hop(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm)
{
  TRP_ROUTE *route=trps_get_selected_route(trps, comm, realm);
  if (route==NULL)
    return NULL;

  return trp_route_get_next_hop(route);
}


/* mark a route as retracted */
static void trps_retract_route(TRPS_INSTANCE *trps, TRP_ROUTE *entry)
{
  trp_route_set_metric(entry, TRP_METRIC_INFINITY);
  trp_route_set_triggered(entry, 1);
}

/* is this route retracted? */
static int trps_route_retracted(TRPS_INSTANCE *trps, TRP_ROUTE *entry)
{
  return (trp_metric_is_infinite(trp_route_get_metric(entry)));
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

  tr_debug("trps_read_message(): message received, %u bytes.", (unsigned) buflen);
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

TRP_RC trps_authorize_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *conn)
{
  /* try to establish a GSS context */
  if (0!=trp_connection_auth(conn, trps->auth_handler, trps->cookie)) {
    tr_notice("trps_authorize_connection: failed to authorize connection");
    trp_connection_close(conn);
    return TRP_ERROR;
  }
  tr_notice("trps_authorize_connection: authorized connection");
  return TRP_SUCCESS;
}

void trps_handle_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *conn)
{
  TR_MSG *msg=NULL;
  TRP_RC rc=TRP_ERROR;

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
}

static TRP_RC trps_validate_update(TRPS_INSTANCE *trps, TRP_UPD *upd)
{
  if (upd==NULL) {
    tr_notice("trps_validate_update: null TRP update.");
    return TRP_BADARG;
  }

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
  TRP_ROUTE *entry=trp_rtable_get_entry(trps->rtable, comm, realm, peer);
  if (entry==NULL)
    return TRP_METRIC_INFINITY;
  return trp_route_get_metric(entry) + trps_cost(trps, peer);
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

static TRP_RC trps_accept_update(TRPS_INSTANCE *trps, TRP_UPD *upd, TRP_INFOREC *rec)
{
  TRP_ROUTE *entry=NULL;

  entry=trp_rtable_get_entry(trps->rtable,
                             trp_inforec_get_comm(rec),
                             trp_inforec_get_realm(rec),
                             trp_inforec_get_next_hop(rec));
  if (entry==NULL) {
    entry=trp_route_new(NULL);
    if (entry==NULL) {
      tr_err("trps_accept_update: unable to allocate new entry.");
      return TRP_NOMEM;
    }

    trp_route_set_comm(entry, trp_inforec_dup_comm(rec));
    trp_route_set_realm(entry, trp_inforec_dup_realm(rec));
    trp_route_set_peer(entry, trp_upd_dup_peer(upd));
    trp_route_set_trust_router(entry, trp_inforec_dup_trust_router(rec));
    trp_route_set_next_hop(entry, trp_inforec_dup_next_hop(rec));
    if ((trp_route_get_comm(entry)==NULL)
       ||(trp_route_get_realm(entry)==NULL)
       ||(trp_route_get_peer(entry)==NULL)
       ||(trp_route_get_trust_router(entry)==NULL)
       ||(trp_route_get_next_hop(entry)==NULL)) {
      /* at least one field could not be allocated */
      tr_err("trps_accept_update: unable to allocate all fields for entry.");
      trp_route_free(entry);
      return TRP_NOMEM;
    }
    trp_rtable_add(trps->rtable, entry);
  }

  /* We now have an entry in the table, whether it's new or not. Update metric and expiry, unless
   * the metric is infinity. An infinite metric can only occur here if we just retracted an existing
   * route (we never accept retractions as new routes), so there is no risk of leaving the expiry
   * time unset on a new route entry. */
  tr_debug("trps_accept_update: accepting route update.");
  trp_route_set_metric(entry, trp_inforec_get_metric(rec));
  trp_route_set_interval(entry, trp_inforec_get_interval(rec));

  /* check whether the trust router has changed */
  if (0!=tr_name_cmp(trp_route_get_trust_router(entry),
                     trp_inforec_get_trust_router(rec))) {
    /* The name changed. Set this route as triggered. */
    tr_debug("trps_accept_update: trust router for route changed.");
    trp_route_set_triggered(entry, 1);
    trp_route_set_trust_router(entry, trp_inforec_dup_trust_router(rec)); /* frees old name */
  }
  if (!trps_route_retracted(trps, entry)) {
    tr_debug("trps_accept_update: route not retracted, setting expiry timer.");
    trp_route_set_expiry(entry, trps_compute_expiry(trps,
                                                     trp_route_get_interval(entry),
                                                     trp_route_get_expiry(entry)));
  }
  return TRP_SUCCESS;
}

static TRP_RC trps_handle_update(TRPS_INSTANCE *trps, TRP_UPD *upd)
{
  unsigned int feas=0;
  TRP_INFOREC *rec=NULL;
  TRP_ROUTE *route=NULL;

  if (trps_validate_update(trps, upd) != TRP_SUCCESS) {
    tr_notice("trps_handle_update: received invalid TRP update.");
    return TRP_ERROR;
  }

  for (rec=trp_upd_get_inforec(upd); rec!=NULL; rec=trp_inforec_get_next(rec)) {
    /* validate/sanity check the record update */
    if (trps_validate_inforec(trps, rec) != TRP_SUCCESS) {
      tr_notice("trps_handle_update: invalid record in TRP update, discarding entire update.");
      return TRP_ERROR;
    }
  }

  for (rec=trp_upd_get_inforec(upd); rec!=NULL; rec=trp_inforec_get_next(rec)) {
    /* determine feasibility */
    feas=trps_check_feasibility(trps, rec);
    tr_debug("trps_handle_update: record feasibility=%d", feas);

    /* do we have an existing route? */
    route=trps_get_route(trps,
                         trp_inforec_get_comm(rec),
                         trp_inforec_get_realm(rec),
                         trp_upd_get_peer(upd));
    if (route!=NULL) {
      /* there was a route table entry already */
      tr_debug("trps_handle_updates: route entry already exists.");
      if (feas) {
        /* Update is feasible. Accept it. */
        trps_accept_update(trps, upd, rec);
      } else {
        /* Update is infeasible. Ignore it unless the trust router has changed. */
        if (0!=tr_name_cmp(trp_route_get_trust_router(route),
                           trp_inforec_get_trust_router(rec))) {
          /* the trust router associated with the route has changed, treat update as a retraction */
          trps_retract_route(trps, route);
        }
      }
    } else {
      /* No existing route table entry. Ignore it unless it is feasible and not a retraction. */
      tr_debug("trps_handle_update: no route entry exists yet.");
      if (feas && trp_metric_is_finite(trp_inforec_get_metric(rec)))
        trps_accept_update(trps, upd, rec);
    }
  }
  return TRP_SUCCESS;
}

static TRP_RC trps_validate_request(TRPS_INSTANCE *trps, TRP_REQ *req)
{
  if (req==NULL) {
    tr_notice("trps_validate_request: null TRP request.");
    return TRP_BADARG;
  }

  if (trp_req_get_comm(req)==NULL) {
    tr_notice("trps_validate_request: received TRP request with null community.");
    return TRP_ERROR;
  }
  
  if (trp_req_get_realm(req)==NULL) {
    tr_notice("trps_validate_request: received TRP request with null realm.");
    return TRP_ERROR;
  }
  
  if (trp_req_get_peer(req)==NULL) {
    tr_notice("trps_validate_request: received TRP request without origin peer information.");
    return TRP_ERROR;
  }
  
  return TRP_SUCCESS;
}

/* choose the best route to comm/realm, optionally excluding routes to a particular peer */
static TRP_ROUTE *trps_find_best_route(TRPS_INSTANCE *trps,
                                        TR_NAME *comm,
                                        TR_NAME *realm,
                                        TR_NAME *exclude_peer)
{
  TRP_ROUTE **entry=NULL;
  TRP_ROUTE *best=NULL;
  size_t n_entry=0;
  unsigned int kk=0;
  unsigned int kk_min=0;
  unsigned int min_metric=TRP_METRIC_INFINITY;

  entry=trp_rtable_get_realm_entries(trps->rtable, comm, realm, &n_entry);
  for (kk=0; kk<n_entry; kk++) {
    if (trp_route_get_metric(entry[kk]) < min_metric) {
      if ((exclude_peer==NULL) || (0!=tr_name_cmp(trp_route_get_peer(entry[kk]),
                                                  exclude_peer))) {
        kk_min=kk;
        min_metric=trp_route_get_metric(entry[kk]);
      } 
    }
  }
  if (trp_metric_is_finite(min_metric))
    best=entry[kk_min];
  
  talloc_free(entry);
  return best;
}

/* TODO: think this through more carefully. At least ought to add hysteresis
 * to avoid flapping between routers or routes. */
TRP_RC trps_update_active_routes(TRPS_INSTANCE *trps)
{
  size_t n_comm=0, ii=0;
  TR_NAME **comm=trp_rtable_get_comms(trps->rtable, &n_comm);
  size_t n_realm=0, jj=0;
  TR_NAME **realm=NULL;
  TRP_ROUTE *best_route=NULL, *cur_route=NULL;
  unsigned int best_metric=0, cur_metric=0;

  for (ii=0; ii<n_comm; ii++) {
    realm=trp_rtable_get_comm_realms(trps->rtable, comm[ii], &n_realm);
    for (jj=0; jj<n_realm; jj++) {
      best_route=trps_find_best_route(trps, comm[ii], realm[jj], NULL);
      if (best_route==NULL)
        best_metric=TRP_METRIC_INFINITY;
      else
        best_metric=trp_route_get_metric(best_route);

      cur_route=trps_get_selected_route(trps, comm[ii], realm[jj]);
      if (cur_route!=NULL) {
        cur_metric=trp_route_get_metric(cur_route);
        if ((best_metric < cur_metric) && (trp_metric_is_finite(best_metric))) {
          /* The new route has a lower metric than the previous, and is finite. Accept. */
          trp_route_set_selected(cur_route, 0);
          trp_route_set_selected(best_route, 1);
        } else if (!trp_metric_is_finite(cur_metric)) /* rejects infinite or invalid metrics */
          trp_route_set_selected(cur_route, 0);
      } else if (trp_metric_is_finite(best_metric)) {
        trp_route_set_selected(best_route, 1);
      }
    }
    if (realm!=NULL)
      talloc_free(realm);
    realm=NULL; n_realm=0;
  }
  if (comm!=NULL)
    talloc_free(comm);
  comm=NULL; n_comm=0;

  return TRP_SUCCESS;
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
  TRP_ROUTE **entry=NULL;
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
    if (!trp_route_is_local(entry[ii]) && trps_expired(trp_route_get_expiry(entry[ii]), &sweep_time)) {
      tr_debug("trps_sweep_routes: route expired.");
      if (!trp_metric_is_finite(trp_route_get_metric(entry[ii]))) {
        /* flush route */
        tr_debug("trps_sweep_routes: metric was infinity, flushing route.");
        trp_rtable_remove(trps->rtable, entry[ii]); /* entry[ii] is no longer valid */
        entry[ii]=NULL;
      } else {
        /* set metric to infinity and reset timer */
        tr_debug("trps_sweep_routes: setting metric to infinity and resetting expiry.");
        trp_route_set_metric(entry[ii], TRP_METRIC_INFINITY);
        trp_route_set_expiry(entry[ii], trps_compute_expiry(trps,
                                                             trp_route_get_interval(entry[ii]),
                                                             trp_route_get_expiry(entry[ii])));
      }
    }
  }

  talloc_free(entry);
  return TRP_SUCCESS;
}

/* select the correct route to comm/realm to be announced to peer */
static TRP_ROUTE *trps_select_realm_update(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer_gssname)
{
  TRP_ROUTE *route;

  /* Take the currently selected route unless it is through the peer we're sending the update to.
   * I.e., enforce the split horizon rule. */
  route=trp_rtable_get_selected_entry(trps->rtable, comm, realm);
  if (route==NULL) {
    /* No selected route, this should only happen if the only route has been retracted,
     * in which case we do not want to advertise it. */
    return NULL;
  }
  tr_debug("trps_select_realm_update: %s vs %s", peer_gssname->buf,
           trp_route_get_peer(route)->buf);
  if (0==tr_name_cmp(peer_gssname, trp_route_get_peer(route))) {
    tr_debug("trps_select_realm_update: matched, finding alternate route");
    /* the selected entry goes through the peer we're reporting to, choose an alternate */
    route=trps_find_best_route(trps, comm, realm, peer_gssname);
    if ((route==NULL) || (!trp_metric_is_finite(trp_route_get_metric(route))))
      return NULL; /* don't advertise a nonexistent or retracted route */
  }
  return route;
}

/* returns an array of pointers to updates (*not* an array of updates). Returns number of entries
 * via n_update parameter. (The allocated space will generally be larger than required, see note in
 * the code.) If triggered is set, sends only triggered updates. */
static TRP_ROUTE **trps_select_updates_for_peer(TALLOC_CTX *memctx,
                                                 TRPS_INSTANCE *trps,
                                                 TR_NAME *peer_gssname,
                                                 int triggered,
                                                 size_t *n_update)
{
  size_t n_comm=0;
  TR_NAME **comm=trp_rtable_get_comms(trps->rtable, &n_comm);
  TR_NAME **realm=NULL;
  size_t n_realm=0;
  size_t ii=0, jj=0;
  TRP_ROUTE *best=NULL;
  TRP_ROUTE **result=NULL;
  size_t n_used=0;

  /* Need to allocate space for the results. For simplicity, we just allocate a block
   * with space for every route table entry to be returned. This is guaranteed to be large
   * enough. If the routing table gets very large, this may be wasteful, but that seems
   * unlikely to be significant in the near future. */
  result=talloc_array(memctx, TRP_ROUTE *, trp_rtable_size(trps->rtable));
  if (result==NULL) {
    talloc_free(comm);
    *n_update=0;
    return NULL;
  }
  
  for (ii=0; ii<n_comm; ii++) {
    realm=trp_rtable_get_comm_realms(trps->rtable, comm[ii], &n_realm);
    for (jj=0; jj<n_realm; jj++) {
      best=trps_select_realm_update(trps, comm[ii], realm[jj], peer_gssname);
      /* If we found a route, add it to the list. If triggered!=0, then only
       * add triggered routes. */
      if ((best!=NULL) && ((!triggered) || trp_route_is_triggered(best)))
        result[n_used++]=best;
    }
    if (realm!=NULL)
      talloc_free(realm);
    realm=NULL;
    n_realm=0;
  }
  if (comm!=NULL)
    talloc_free(comm);

  *n_update=n_used;
  return result;
}

/* add metrics */
static unsigned int trps_metric_add(unsigned int m1, unsigned int m2)
{
  if (trp_metric_is_invalid(m1) || trp_metric_is_invalid(m2))
    return TRP_METRIC_INVALID;

  if (trp_metric_is_infinite(m1) || trp_metric_is_infinite(m2))
    return TRP_METRIC_INFINITY;

  if (trp_metric_is_finite(m1+m2))
    return m1+m2;
  else
    return TRP_METRIC_INFINITY;
}

/* convert an rentry into a new trp update info record */
static TRP_INFOREC *trps_route_to_inforec(TALLOC_CTX *mem_ctx, TRPS_INSTANCE *trps, TRP_ROUTE *route)
{
  TRP_INFOREC *rec=trp_inforec_new(mem_ctx, TRP_INFOREC_TYPE_ROUTE);
  unsigned int linkcost=0;

  if (rec!=NULL) {
    if (trp_route_is_local(route))
      linkcost=0;
    else {
      linkcost=trp_peer_get_linkcost(trps_get_peer_by_gssname(trps,
                                                              trp_route_get_peer(route)));
    }

    /* Note that we leave the next hop empty since the recipient fills that in.
     * This is where we add the link cost (currently always 1) to the next peer. */
    if ((trp_inforec_set_comm(rec, trp_route_dup_comm(route)) != TRP_SUCCESS)
       ||(trp_inforec_set_realm(rec, trp_route_dup_realm(route)) != TRP_SUCCESS)
       ||(trp_inforec_set_trust_router(rec, trp_route_dup_trust_router(route)) != TRP_SUCCESS)
       ||(trp_inforec_set_metric(rec,
                                 trps_metric_add(trp_route_get_metric(route),
                                                 linkcost)) != TRP_SUCCESS)
       ||(trp_inforec_set_interval(rec, trps_get_update_interval(trps)) != TRP_SUCCESS)) {
      tr_err("trps_route_to_inforec: error creating route update.");
      talloc_free(rec);
      rec=NULL;
    }
  }
  return rec;
}

/* all routes to a single peer, unless comm/realm are specified (both or neither must be NULL) */
static TRP_RC trps_update_one_peer(TRPS_INSTANCE *trps,
                                   TRP_PEER *peer,
                                   TRP_UPDATE_TYPE update_type,
                                   TR_NAME *comm,
                                   TR_NAME *realm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_MSG msg; /* not a pointer! */
  TRP_UPD *upd=NULL;
  TRP_ROUTE **update_list=NULL;
  TRP_INFOREC *rec=NULL;
  size_t n_updates=0, ii=0;
  char *encoded=NULL;
  TRP_RC rc=TRP_ERROR;
  TR_NAME *peer_label=trp_peer_get_label(peer);

  switch (update_type) {
  case TRP_UPDATE_TRIGGERED:
    tr_debug("trps_update_one_peer: preparing triggered route update for %.*s",
             peer_label->len, peer_label->buf);
    break;
  case TRP_UPDATE_SCHEDULED:
    tr_debug("trps_update_one_peer: preparing scheduled route update for %.*s",
             peer_label->len, peer_label->buf);
    break;
  case TRP_UPDATE_REQUESTED:
    tr_debug("trps_update_one_peer: preparing requested route update for %.*s",
             peer_label->len, peer_label->buf);
  }

  /* do not fill in peer, recipient does that */
  if ((comm==NULL) && (realm==NULL)) {
    /* do all realms */
    update_list=trps_select_updates_for_peer(tmp_ctx,
                                             trps,
                                             peer_label,
                                             update_type==TRP_UPDATE_TRIGGERED,
                                            &n_updates);
  } else if ((comm!=NULL) && (realm!=NULL)) {
    /* a single community/realm was requested */
    update_list=talloc(tmp_ctx, TRP_ROUTE *);
    if (update_list==NULL) {
      tr_err("trps_update_one_peer: could not allocate update_list.");
      rc=TRP_NOMEM;
      goto cleanup;
    }
    *update_list=trps_select_realm_update(trps, comm, realm, peer_label);
    if (*update_list==NULL) {
      /* we have no actual update to send back, MUST send a retraction */
      tr_debug("trps_update_one_peer: community/realm without route requested, sending mandatory retraction.");
      *update_list=trp_route_new(update_list);
      trp_route_set_comm(*update_list, tr_dup_name(comm));
      trp_route_set_realm(*update_list, tr_dup_name(realm));
      trp_route_set_peer(*update_list, tr_new_name(""));
      trp_route_set_metric(*update_list, TRP_METRIC_INFINITY);
      trp_route_set_trust_router(*update_list, tr_new_name(""));
      trp_route_set_next_hop(*update_list, tr_new_name(""));
    }
    n_updates=1;
  } else {
    tr_err("trps_update_one_peer: error: only comm or realm was specified.");
    rc=TRP_ERROR;
    goto cleanup;
  }
  if ((n_updates>0) && (update_list!=NULL)) {
    tr_debug("trps_update_one_peer: sending %u update records.", (unsigned int)n_updates);
    upd=trp_upd_new(tmp_ctx);

    for (ii=0; ii<n_updates; ii++) {
      rec=trps_route_to_inforec(tmp_ctx, trps, update_list[ii]);
      if (rec==NULL) {
        tr_err("trps_update_one_peer: could not create all update records.");
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
      tr_err("trps_update_one_peer: error encoding update.");
      rc=TRP_ERROR;
      goto cleanup;
    }

    tr_debug("trps_update_one_peer: adding message to queue.");
    if (trps_send_msg(trps, peer, encoded) != TRP_SUCCESS)
      tr_err("trps_update_one_peer: error queueing update.");
    else
      tr_debug("trps_update_one_peer: update queued successfully.");

    tr_msg_free_encoded(encoded);
    encoded=NULL;
    trp_upd_free(upd);
    upd=NULL;
  }

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

/* all routes to all peers */
TRP_RC trps_update(TRPS_INSTANCE *trps, TRP_UPDATE_TYPE update_type)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_PTABLE_ITER *iter=trp_ptable_iter_new(tmp_ctx);
  TRP_PEER *peer=NULL;
  TRP_RC rc=TRP_SUCCESS;

  if (trps->ptable==NULL)
    return TRP_SUCCESS; /* no peers, nothing to do */

  if (iter==NULL) {
    tr_err("trps_update: failed to allocate peer table iterator.");
    talloc_free(tmp_ctx);
    return TRP_NOMEM;
  }

  for (peer=trp_ptable_iter_first(iter, trps->ptable);
       peer!=NULL && rc==TRP_SUCCESS;
       peer=trp_ptable_iter_next(iter))
  {
    if (!trps_peer_connected(trps, peer)) {
      TR_NAME *peer_label=trp_peer_get_label(peer);
      tr_debug("trps_update: no TRP connection to %.*s, skipping.",
               peer_label->len, peer_label->buf);
      continue;
    }
    rc=trps_update_one_peer(trps, peer, update_type, NULL, NULL);
  }
  
  trp_ptable_iter_free(iter);
  trp_rtable_clear_triggered(trps->rtable); /* don't re-send triggered updates */
  talloc_free(tmp_ctx);
  return rc;
}        

TRP_RC trps_add_route(TRPS_INSTANCE *trps, TRP_ROUTE *route)
{
  trp_rtable_add(trps->rtable, route); /* should return status */
  return TRP_SUCCESS; 
}

/* steals the peer object */
TRP_RC trps_add_peer(TRPS_INSTANCE *trps, TRP_PEER *peer)
{
  if (trps->ptable==NULL) {
    trps->ptable=trp_ptable_new(trps);
    if (trps->ptable==NULL)
      return TRP_NOMEM;
  }
  return trp_ptable_add(trps->ptable, peer);
}

TRP_PEER *trps_get_peer_by_gssname(TRPS_INSTANCE *trps, TR_NAME *gssname)
{
  if (trps->ptable==NULL)
    return NULL;

  return trp_ptable_find_gss_name(trps->ptable, gssname);
}

TRP_PEER *trps_get_peer_by_servicename(TRPS_INSTANCE *trps, TR_NAME *servicename)
{
  if (trps->ptable==NULL)
    return NULL;

  return trp_ptable_find_servicename(trps->ptable, servicename);
}

int trps_peer_connected(TRPS_INSTANCE *trps, TRP_PEER *peer)
{
  TRPC_INSTANCE *trpc=trps_find_trpc(trps, peer);
  if (trpc==NULL)
    return 0;

  if (trpc_get_status(trpc)==TRP_CONNECTION_UP)
    return 1;
  else
    return 0;
}


static TRP_RC trps_handle_request(TRPS_INSTANCE *trps, TRP_REQ *req)
{
  TR_NAME *comm=NULL;
  TR_NAME *realm=NULL;

  tr_debug("trps_handle_request: handling TRP request.");

  if (trps_validate_request(trps, req) != TRP_SUCCESS) {
    tr_notice("trps_handle_request: received invalid TRP request.");
    return TRP_ERROR;
  }

  if (!trp_req_is_wildcard(req)) {
    comm=trp_req_get_comm(req);
    realm=trp_req_get_realm(req);
    tr_debug("trps_handle_request: route for %.*s/%.*s requested.",
             comm->len, comm->buf, realm->len, realm->buf);
  } else {
    tr_debug("trps_handle_request: all routes requested.");
    /* leave comm/realm NULL */
  }
  return trps_update_one_peer(trps,
                              trps_get_peer_by_gssname(trps, trp_req_get_peer(req)),
                              TRP_UPDATE_REQUESTED,
                              comm,
                              realm);
}


TRP_RC trps_handle_tr_msg(TRPS_INSTANCE *trps, TR_MSG *tr_msg)
{
  TRP_RC rc=TRP_ERROR;

  switch (tr_msg_get_msg_type(tr_msg)) {
  case TRP_UPDATE:
    rc=trps_handle_update(trps, tr_msg_get_trp_upd(tr_msg));
    if (rc==TRP_SUCCESS) {
      rc=trps_update_active_routes(trps);
      trps_update(trps, TRP_UPDATE_TRIGGERED); /* send any triggered routes */
    }
    return rc;

  case TRP_REQUEST:
    rc=trps_handle_request(trps, tr_msg_get_trp_req(tr_msg));
    return rc;

  default:
    /* unknown error or one we don't care about (e.g., TID messages) */
    return TRP_ERROR;
  }
}

/* send wildcard route request to a peer */
TRP_RC trps_wildcard_route_req(TRPS_INSTANCE *trps, TR_NAME *peer_servicename)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_PEER *peer=trps_get_peer_by_servicename(trps, peer_servicename);
  TR_MSG msg; /* not a pointer */
  TRP_REQ *req=trp_req_new(tmp_ctx);
  char *encoded=NULL;
  TRP_RC rc=TRP_ERROR;

  if (peer==NULL) {
    tr_err("trps_wildcard_route_req: unknown peer (%.*s).", peer_servicename->len, peer_servicename->buf);
    rc=TRP_BADARG;
    goto cleanup;
  }
  if ((req==NULL) || (trp_req_make_wildcard(req)!=TRP_SUCCESS)) {
    tr_err("trps_wildcard_route_req: unable to create wildcard TRP request.");
    rc=TRP_NOMEM;
    goto cleanup;
  }

  tr_msg_set_trp_req(&msg, req);
  encoded=tr_msg_encode(&msg);
  if (encoded==NULL) {
    tr_err("trps_wildcard_route_req: error encoding wildcard TRP request.");
    rc=TRP_ERROR;
    goto cleanup;
  }

  tr_debug("trps_wildcard_route_req: adding message to queue.");
  if (trps_send_msg(trps, peer, encoded) != TRP_SUCCESS) {
    tr_err("trps_wildcard_route_req: error queueing request.");
    rc=TRP_ERROR;
  } else {
    tr_debug("trps_wildcard_route_req: request queued successfully.");
    rc=TRP_SUCCESS;
  }

cleanup:
  if (encoded!=NULL)
    tr_msg_free_encoded(encoded);
  if (req!=NULL)
    trp_req_free(req);

  talloc_free(tmp_ctx);
  return rc;
}
