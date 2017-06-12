/*
 * Copyright (c) 2016, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <fcntl.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <glib.h>
#include <string.h>

#include <gsscon.h>
#include <tr_comm.h>
#include <tr_apc.h>
#include <tr_rp.h>
#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <tr_gss.h>
#include <trp_ptable.h>
#include <trp_rtable.h>
#include <tr_debug.h>
#include <tr_util.h>

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
  return tr_mq_pop(trps->mq, 0);
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

void trps_set_ctable(TRPS_INSTANCE *trps, TR_COMM_TABLE *comm)
{
  trps->ctable=comm;
}

void trps_set_ptable(TRPS_INSTANCE *trps, TRP_PTABLE *ptable)
{
  if (trps->ptable!=NULL)
    trp_ptable_free(trps->ptable);
  trps->ptable=ptable;
}

void trps_set_peer_status_callback(TRPS_INSTANCE *trps, void (*cb)(TRP_PEER *, void *), void *cookie)
{
  TRP_PTABLE_ITER *iter=NULL;
  TRP_PEER *peer=NULL;
  if (trps->ptable==NULL)
    return;

  iter=trp_ptable_iter_new(NULL);
  for (peer=trp_ptable_iter_first(iter, trps->ptable); peer!=NULL; peer=trp_ptable_iter_next(iter))
    trp_peer_set_conn_status_cb(peer, cb, cookie);
  trp_ptable_iter_free(iter);
}

/* Get the label peers will know us by - needs to match trp_peer_get_label() output.
 * There is no get, only dup, because we don't store the label except when requested. */
TR_NAME *trps_dup_label(TRPS_INSTANCE *trps)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_NAME *label=NULL;
  char *s=talloc_asprintf(tmp_ctx, "%s:%u", trps->hostname, trps->port);
  if (s==NULL)
    goto cleanup;
  label=tr_new_name(s);

cleanup:
  talloc_free(tmp_ctx);
  return label;
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

/* Listens on all interfaces. Returns number of sockets opened. Their
 * descriptors are stored in *fd_out, which should point to space for
 * up to max_fd of them. */
static size_t trps_listen(TRPS_INSTANCE *trps, int port, int *fd_out, size_t max_fd) 
{
  int rc = 0;
  int conn = -1;
  int optval=0;
  struct addrinfo *ai=NULL;
  struct addrinfo *ai_head=NULL;
  struct addrinfo hints={.ai_flags=AI_PASSIVE,
                         .ai_family=AF_UNSPEC,
                         .ai_socktype=SOCK_STREAM,
                         .ai_protocol=IPPROTO_TCP};
  char *port_str=NULL;
  size_t n_opened=0;

  port_str=talloc_asprintf(NULL, "%d", port);
  if (port_str==NULL) {
    tr_debug("trps_listen: unable to allocate port.");
    return -1;
  }
  getaddrinfo(NULL, port_str, &hints, &ai_head);
  talloc_free(port_str);

  for (ai=ai_head,n_opened=0; (ai!=NULL)&&(n_opened<max_fd); ai=ai->ai_next) {
    if (0 > (conn = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))) {
      tr_debug("trps_listen: unable to open socket.");
      continue;
    }

    optval=1;
    if (0!=setsockopt(conn, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)))
      tr_debug("trps_listen: unable to set SO_REUSEADDR."); /* not fatal? */

    if (ai->ai_family==AF_INET6) {
      /* don't allow IPv4-mapped IPv6 addresses (per RFC4942, not sure
       * if still relevant) */
      if (0!=setsockopt(conn, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval))) {
        tr_debug("trps_listen: unable to set IPV6_V6ONLY. Skipping interface.");
        close(conn);
        continue;
      }
    }

    rc=bind(conn, ai->ai_addr, ai->ai_addrlen);
    if (rc<0) {
      tr_debug("trps_listen: unable to bind to socket.");
      close(conn);
      continue;
    }

    if (0>listen(conn, 512)) {
      tr_debug("trps_listen: unable to listen on bound socket.");
      close(conn);
      continue;
    }

    /* ok, this one worked. Save it */
    fd_out[n_opened++]=conn;
  }
  freeaddrinfo(ai_head);

  if (n_opened==0) {
    tr_debug("trps_listen: no addresses available for listening.");
    return -1;
  }
  
  tr_debug("trps_listen: TRP Server listening on port %d on %d socket%s",
           port,
           n_opened,
           (n_opened==1)?"":"s");

  return n_opened;
}

/* get the currently selected route if available */
TRP_ROUTE *trps_get_route(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer)
{
  return trp_rtable_get_entry(trps->rtable, comm, realm, peer);
}

TRP_ROUTE *trps_get_selected_route(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm)
{
  tr_debug("trps_get_selected_route: entered. trps=%p, comm=%p, realm=%p", trps, comm, realm);
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
  TRP_PEER *peer=NULL; /* entry in the peer table */
  TR_NAME *conn_peer=NULL; /* name from the TRP_CONN, which comes from the gss context */

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

  tr_debug("trps_read_message: message received, %u bytes.", (unsigned) buflen);
  tr_debug("trps_read_message: %.*s", buflen, buf);

  *msg=tr_msg_decode(buf, buflen);
  free(buf);
  if (*msg==NULL)
    return TRP_NOPARSE;

  conn_peer=trp_connection_get_peer(conn);
  if (conn_peer==NULL) {
    tr_err("trps_read_message: connection has no peer name");
    return TRP_ERROR;
  }

  peer=trps_get_peer_by_gssname(trps, conn_peer);
  if (peer==NULL) {
    tr_err("trps_read_message: could not find peer with gssname=%s", trp_connection_get_gssname(conn));
    return TRP_ERROR;
  }

  /* verify we received a message we support, otherwise drop it now */
  switch (tr_msg_get_msg_type(*msg)) {
  case TRP_UPDATE:
    trp_upd_set_peer(tr_msg_get_trp_upd(*msg), tr_dup_name(conn_peer));
    trp_upd_set_next_hop(tr_msg_get_trp_upd(*msg), trp_peer_get_server(peer), 0); /* TODO: 0 should be the configured TID port */
    /* update provenance if necessary */
    trp_upd_add_to_provenance(tr_msg_get_trp_upd(*msg), trp_peer_get_label(peer));
    break;

  case TRP_REQUEST:
    trp_req_set_peer(tr_msg_get_trp_req(*msg), tr_dup_name(conn_peer));
    break;

  default:
    tr_debug("trps_read_message: received unsupported message from %.*s", conn_peer->len, conn_peer->buf);
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
                      void *cookie,
                      int *fd_out,
                      size_t max_fd)
{
  size_t n_fd=0;
  size_t ii=0;

  n_fd=trps_listen(trps, port, fd_out, max_fd);
  if (n_fd==0)
    tr_debug("trps_get_listener: Error opening port %d.");
  else {
    /* opening port succeeded */
    tr_debug("trps_get_listener: Opened port %d.", port);
    
    /* make the sockets non-blocking */
    for (ii=0; ii<n_fd; ii++) {
      if (0 != fcntl(fd_out[ii], F_SETFL, O_NONBLOCK)) {
        tr_debug("trps_get_listener: Error setting O_NONBLOCK.");
        for (ii=0; ii<n_fd; ii++) {
          close(fd_out[ii]);
          fd_out[ii]=-1;
        }
        n_fd=0;
        break;
      }
    }
  }

  if (n_fd>0) {
    /* store the caller's request handler & cookie */
    trps->msg_handler = msg_handler;
    trps->auth_handler = auth_handler;
    trps->hostname = talloc_strdup(trps, hostname);
    trps->port = port;
    trps->cookie = cookie;
  }

  return n_fd;
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

/* TODO: check realm/comm, now part of the update instead of inforec */
static TRP_RC trps_validate_update(TRPS_INSTANCE *trps, TRP_UPD *upd)
{
  if (upd==NULL) {
    tr_notice("trps_validate_update: null TRP update.");
    return TRP_BADARG;
  }

  if (trp_upd_get_realm(upd)==NULL) {
    tr_notice("trps_validate_update: received TRP update without realm.");
    return TRP_ERROR;
  }

  if (trp_upd_get_comm(upd)==NULL) {
    tr_notice("trps_validate_update: received TRP update without community.");
    return TRP_ERROR;
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
    if ((trp_inforec_get_trust_router(rec)==NULL)
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

  case TRP_INFOREC_TYPE_COMMUNITY:
    /* TODO: validate community updates */
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

static int trps_check_feasibility(TRPS_INSTANCE *trps, TR_NAME *realm, TR_NAME *comm, TRP_INFOREC *rec)
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
  next_hop=trps_get_next_hop(trps, comm, realm);
  if ((next_hop!=NULL)
     && (0==tr_name_cmp(next_hop,trp_inforec_get_next_hop(rec)))) {
    return 1;
  }
    

  /* compare the existing metric we advertise to what we would advertise
   * if we accept this update */
  current_metric=trps_advertised_metric(trps, comm, realm, trp_inforec_get_next_hop(rec));
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
  if (0!=clock_gettime(TRP_CLOCK, ts)) {
    tr_err("trps_compute_expiry: could not read realtime clock.");
    ts->tv_sec=0;
    ts->tv_nsec=0;
  }
  tr_debug("trps_compute_expiry: tv_sec=%u, interval=%u, small_factor*interval=%u", ts->tv_sec, interval, small_factor*interval);
  ts->tv_sec += small_factor*interval;
  return ts;
}

static TRP_RC trps_accept_update(TRPS_INSTANCE *trps, TRP_UPD *upd, TRP_INFOREC *rec)
{
  TRP_ROUTE *entry=NULL;

  entry=trp_rtable_get_entry(trps->rtable,
                             trp_upd_get_comm(upd),
                             trp_upd_get_realm(upd),
                             trp_inforec_get_next_hop(rec));
  if (entry==NULL) {
    entry=trp_route_new(NULL);
    if (entry==NULL) {
      tr_err("trps_accept_update: unable to allocate new entry.");
      return TRP_NOMEM;
    }

    trp_route_set_comm(entry, trp_upd_dup_comm(upd));
    trp_route_set_realm(entry, trp_upd_dup_realm(upd));
    trp_route_set_peer(entry, trp_upd_dup_peer(upd));
    trp_route_set_trust_router(entry, trp_inforec_dup_trust_router(rec));
    trp_route_set_next_hop(entry, trp_inforec_dup_next_hop(rec));
    /* TODO: pass next hop port (now defaults to TID_PORT) --jlr */
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


static TRP_RC trps_handle_inforec_route(TRPS_INSTANCE *trps, TRP_UPD *upd, TRP_INFOREC *rec)
{
  TRP_ROUTE *route=NULL;
  unsigned int feas=0;

  /* determine feasibility */
  feas=trps_check_feasibility(trps, trp_upd_get_realm(upd), trp_upd_get_comm(upd), rec);
  tr_debug("trps_handle_update: record feasibility=%d", feas);

  /* do we have an existing route? */
  route=trps_get_route(trps,
                       trp_upd_get_comm(upd),
                       trp_upd_get_realm(upd),
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

  return TRP_SUCCESS;
}

static int trps_name_in_provenance(TR_NAME *name, json_t *prov)
{
  size_t ii=0;
  TR_NAME *this_name=NULL;
  const char *s=NULL;

  if (prov==NULL)
    return 0; /* no provenance list, so it has no names in it */

  /* now check to see if name is in the provenance */
  for (ii=0; ii<json_array_size(prov); ii++) {
    s=json_string_value(json_array_get(prov, ii));
    if (s==NULL) {
      tr_debug("trps_name_in_provenance: empty entry in provenance list.");
      continue;
    }

    this_name=tr_new_name(s);
    if (this_name==NULL) {
      tr_debug("trps_name_in_provenance: unable to allocate name.");
      return -1;
    }
    if (0==tr_name_cmp(name, this_name)) {
      tr_free_name(this_name);
      return 1;
    }
    tr_free_name(this_name);
  }
  return 0;
}

static TR_COMM *trps_create_new_comm(TALLOC_CTX *mem_ctx, TR_NAME *comm_id, TRP_INFOREC *rec)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM *comm=tr_comm_new(tmp_ctx);
  
  if (comm==NULL) {
    tr_debug("trps_create_new_comm: unable to allocate new community.");
    goto cleanup;
  }
  /* fill in the community with info */
  tr_comm_set_id(comm, tr_dup_name(comm_id));
  if (tr_comm_get_id(comm)==NULL) {
    tr_debug("trps_create_new_comm: unable to allocate community name.");
    comm=NULL;
    goto cleanup;
  }
  tr_comm_set_type(comm, trp_inforec_get_comm_type(rec));
  if (trp_inforec_get_apcs(rec)!=NULL) {
    tr_comm_set_apcs(comm, tr_apc_dup(tmp_ctx, trp_inforec_get_apcs(rec)));
    if (tr_comm_get_apcs(comm)==NULL) {
      tr_debug("trps_create_new_comm: unable to allocate APC list.");
      comm=NULL;
      goto cleanup;
    }
  }
  if (trp_inforec_get_owner_realm(rec)!=NULL) {
    tr_comm_set_owner_realm(comm, tr_dup_name(trp_inforec_get_owner_realm(rec)));
    if (tr_comm_get_owner_realm(comm)==NULL) {
      tr_debug("trps_create_new_comm: unable to allocate owner realm name.");
      comm=NULL;
      goto cleanup;
    }
  }
  if (trp_inforec_get_owner_contact(rec)!=NULL) {
    tr_comm_set_owner_contact(comm, tr_dup_name(trp_inforec_get_owner_contact(rec)));
    if (tr_comm_get_owner_contact(comm)==NULL) {
      tr_debug("trps_create_new_comm: unable to allocate owner contact.");
      comm=NULL;
      goto cleanup;
    }
  }
  comm->expiration_interval=trp_inforec_get_exp_interval(rec);
  talloc_steal(mem_ctx, comm);
  
cleanup:
  talloc_free(tmp_ctx);
  return comm;
}

static TR_RP_REALM *trps_create_new_rp_realm(TALLOC_CTX *mem_ctx, TR_NAME *realm_id, TRP_INFOREC *rec)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_RP_REALM *rp=tr_rp_realm_new(tmp_ctx);
  
  if (rp==NULL) {
    tr_debug("trps_create_new_rp_realm: unable to allocate new realm.");
    goto cleanup;
  }
  /* fill in the realm */
  tr_rp_realm_set_id(rp, tr_dup_name(realm_id));
  if (tr_rp_realm_get_id(rp)==NULL) {
    tr_debug("trps_create_new_rp_realm: unable to allocate realm name.");
    rp=NULL;
    goto cleanup;
  }
  talloc_steal(mem_ctx, rp);
  
cleanup:
  talloc_free(tmp_ctx);
  return rp;
}

static TR_IDP_REALM *trps_create_new_idp_realm(TALLOC_CTX *mem_ctx, TR_NAME *realm_id, TRP_INFOREC *rec)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_IDP_REALM *idp=tr_idp_realm_new(tmp_ctx);
  
  if (idp==NULL) {
    tr_debug("trps_create_new_idp_realm: unable to allocate new realm.");
    goto cleanup;
  }
  /* fill in the realm */
  tr_idp_realm_set_id(idp, tr_dup_name(realm_id));
  if (tr_idp_realm_get_id(idp)==NULL) {
    tr_debug("trps_create_new_idp_realm: unable to allocate realm name.");
    idp=NULL;
    goto cleanup;
  }
  if (trp_inforec_get_apcs(rec)!=NULL) {
    tr_idp_realm_set_apcs(idp, tr_apc_dup(tmp_ctx, trp_inforec_get_apcs(rec)));
    if (tr_idp_realm_get_apcs(idp)==NULL) {
      tr_debug("trps_create_new_idp_realm: unable to allocate APC list.");
      idp=NULL;
      goto cleanup;
    }
  }
  idp->origin=TR_REALM_DISCOVERED;
  
  talloc_steal(mem_ctx, idp);
  
cleanup:
  talloc_free(tmp_ctx);
  return idp;
}

static TRP_RC trps_handle_inforec_comm(TRPS_INSTANCE *trps, TRP_UPD *upd, TRP_INFOREC *rec)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_NAME *comm_id=trp_upd_get_comm(upd);
  TR_NAME *realm_id=trp_upd_get_realm(upd);
  TR_NAME *origin_id=NULL;
  TR_NAME *our_peer_label=NULL;
  TR_COMM *comm=NULL;
  TR_RP_REALM *rp_realm=NULL;
  TR_IDP_REALM *idp_realm=NULL;
  struct timespec expiry={0,0};
  TRP_RC rc=TRP_ERROR;

  if ((comm_id==NULL) || (realm_id==NULL))
    goto cleanup;

  origin_id=trp_inforec_dup_origin(rec);
  if (origin_id==NULL)
    goto cleanup;
    
  /* see whether we want to add this */
  our_peer_label=trps_dup_label(trps);
  if (our_peer_label==NULL) {
    tr_debug("trps_handle_inforec_comm: unable to allocate peer label.");
    goto cleanup;
  }

  if (trps_name_in_provenance(our_peer_label, trp_inforec_get_provenance(rec)))
    tr_debug("trps_handle_inforec_comm: rejecting community inforec to avoid provenance loop.");
  else {
    /* no loop occurring, accept the update */
    comm=tr_comm_table_find_comm(trps->ctable, comm_id);
    if (comm==NULL) {
      tr_debug("trps_handle_inforec_comm: unknown community %.*s in inforec, creating it.",
               comm_id->len, comm_id->buf);
      comm=trps_create_new_comm(tmp_ctx, comm_id, rec);
      if (comm==NULL) {
        tr_debug("trps_handle_inforec_comm: unable to create new community.");
        goto cleanup;
      }
      tr_comm_table_add_comm(trps->ctable, comm);
    }
    /* TODO: see if other comm data match the new inforec and update or complain */

    trps_compute_expiry(trps, trp_inforec_get_interval(rec), &expiry);
    if ((expiry.tv_sec==0)&&(expiry.tv_nsec==0))
      goto cleanup;

    switch (trp_inforec_get_role(rec)) {
    case TR_ROLE_RP:
      rp_realm=tr_rp_realm_lookup(trps->ctable->rp_realms, realm_id);
      if (rp_realm==NULL) {
        tr_debug("trps_handle_inforec_comm: unknown RP realm %.*s in inforec, creating it.",
                 realm_id->len, realm_id->buf);
        rp_realm=trps_create_new_rp_realm(tmp_ctx, realm_id, rec);
        if (rp_realm==NULL) {
          tr_debug("trps_handle_inforec_comm: unable to create new RP realm.");
          /* we may leave an unused community in the table, but it will only last until
           * the next table sweep if it does not get any realms before that happens */
          goto cleanup;
        }
        tr_comm_table_add_rp_realm(trps->ctable, rp_realm);
      }
      /* TODO: if realm existed, see if data match the new inforec and update or complain */
      tr_comm_add_rp_realm(trps->ctable, comm, rp_realm, trp_inforec_get_interval(rec), trp_inforec_get_provenance(rec), &expiry);
      tr_debug("trps_handle_inforec_comm: added RP realm %.*s to comm %.*s (origin %.*s).",
               realm_id->len, realm_id->buf,
               comm_id->len, comm_id->buf,
               origin_id->len, origin_id->buf);
      break;
    case TR_ROLE_IDP:
      idp_realm=tr_idp_realm_lookup(trps->ctable->idp_realms, realm_id);
      if (idp_realm==NULL) {
        tr_debug("trps_handle_inforec_comm: unknown IDP realm %.*s in inforec, creating it.",
                 realm_id->len, realm_id->buf);
        idp_realm=trps_create_new_idp_realm(tmp_ctx, realm_id, rec);
        if (idp_realm==NULL) {
          tr_debug("trps_handle_inforec_comm: unable to create new IDP realm.");
          /* we may leave an unused community in the table, but it will only last until
           * the next table sweep if it does not get any realms before that happens */
          goto cleanup;
        }
        tr_comm_table_add_idp_realm(trps->ctable, idp_realm);
      }
      /* TODO: if realm existed, see if data match the new inforec and update or complain */
      tr_comm_add_idp_realm(trps->ctable, comm, idp_realm, trp_inforec_get_interval(rec), trp_inforec_get_provenance(rec), &expiry);
      tr_debug("trps_handle_inforec_comm: added IDP realm %.*s to comm %.*s (origin %.*s).",
               realm_id->len, realm_id->buf,
               comm_id->len, comm_id->buf,
               origin_id->len, origin_id->buf);
      break;
    default:
      tr_debug("trps_handle_inforec_comm: unable to add realm.");
      goto cleanup;
    }
  } 

  rc=TRP_SUCCESS;

cleanup:
  if (our_peer_label!=NULL)
    tr_free_name(our_peer_label);
  if (origin_id!=NULL)
    tr_free_name(origin_id);
  talloc_free(tmp_ctx);
  return rc;
}

/**
 * Apply applicable TRP_INBOUND filters to an inforec. Rejects everything if peer has no filters.
 *
 * @param trps Active TRPS instance
 * @param peer_name Name of peer that sent this inforec
 * @param rec Inforec to filter
 * @return 1 if accepted by the filter, 0 otherwise
 */
static int trps_filter_inbound_inforec(TRPS_INSTANCE *trps, TR_NAME *peer_name, TRP_INFOREC *rec)
{
  TRP_PEER *peer=NULL;
  TR_FILTER_ACTION action=TR_FILTER_ACTION_REJECT;

  /* Look up the peer. For inbound messages, the peer is identified by its GSS name */
  peer=trps_get_peer_by_gssname(trps, peer_name);
  if (peer==NULL) {
    tr_err("trps_filter_inbound_inforec: received inforec from unknown peer (%.*s), rejecting.",
           peer_name->len,
           peer_name->buf);
    return 0;
  }

  /* tr_filter_apply() and tr_filter_set_get() handle null filter sets/filters by rejecting */
  if ((TR_FILTER_NO_MATCH==tr_filter_apply(rec,
                                           tr_filter_set_get(peer->filters, TR_FILTER_TYPE_TRP_INBOUND),
                                           NULL,
                                           &action))
      || (action!=TR_FILTER_ACTION_ACCEPT)) {
    /* either the filter did not match or it matched a reject rule */
    return 0;
  }

  /* filter matched an accept rule */
  return 1;
}


static TRP_RC trps_handle_update(TRPS_INSTANCE *trps, TRP_UPD *upd)
{
  TRP_INFOREC *rec=NULL;

  if (trps_validate_update(trps, upd) != TRP_SUCCESS) {
    tr_notice("trps_handle_update: received invalid TRP update.");
    return TRP_ERROR;
  }

  for (rec=trp_upd_get_inforec(upd); rec!=NULL; rec=trp_inforec_get_next(rec)) {
    /* validate/sanity check the record update */
    if (trps_validate_inforec(trps, rec) != TRP_SUCCESS) {
      tr_notice("trps_handle_update: invalid inforec in TRP update, discarding entire update.");
      return TRP_ERROR;
    }
  }

  for (rec=trp_upd_get_inforec(upd); rec!=NULL; rec=trp_inforec_get_next(rec)) {
    if (!trps_filter_inbound_inforec(trps, trp_upd_get_peer(upd), rec)) {
      tr_debug("trps_handle_update: inforec rejected by filter.");
      continue; /* just go on to the next record */
    }

    switch (trp_inforec_get_type(rec)) {
    case TRP_INFOREC_TYPE_ROUTE:
      tr_debug("trps_handle_update: handling route inforec.");
      if (TRP_SUCCESS!=trps_handle_inforec_route(trps, upd, rec))
        tr_notice("trps_handle_update: error handling route inforec.");
      break;
    case TRP_INFOREC_TYPE_COMMUNITY:
      tr_debug("trps_handle_update: handling community inforec.");
      if (TRP_SUCCESS!=trps_handle_inforec_comm(trps, upd, rec))
        tr_notice("trps_handle_update: error handling community inforec.");

      break;
    default:
      tr_notice("trps_handle_update: unsupported inforec in TRP update.");
      break;
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
  return (tr_cmp_timespec(curtime, expiry) >= 0);
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
  if (0!=clock_gettime(TRP_CLOCK, &sweep_time)) {
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


static char *timespec_to_str(struct timespec *ts)
{
  struct tm tm;
  char *s=NULL;

  if (localtime_r(&(ts->tv_sec), &tm)==NULL)
    return NULL;

  s=malloc(40); /* long enough to contain strftime result */
  if (s==NULL)
    return NULL;

  if (strftime(s, 40, "%F %T", &tm)==0) {
    free(s);
    return NULL;
  }
  return s;
}


/* Sweep for expired communities/realms/memberships. */
TRP_RC trps_sweep_ctable(TRPS_INSTANCE *trps)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct timespec sweep_time={0,0};
  TR_COMM_MEMB *memb=NULL;
  TR_COMM_ITER *iter=NULL;
  TRP_RC rc=TRP_ERROR;

  /* use a single time for the entire sweep */
  if (0!=clock_gettime(TRP_CLOCK, &sweep_time)) {
    tr_err("trps_sweep_ctable: could not read realtime clock.");
    sweep_time.tv_sec=0;
    sweep_time.tv_nsec=0;
    goto cleanup;
  }

  /* iterate all memberships */
  iter=tr_comm_iter_new(tmp_ctx);
  if (iter==NULL) {
    tr_err("trps_sweep_ctable: unable to allocate iterator.");
    rc=TRP_NOMEM;
    goto cleanup;
  }
  for (memb=tr_comm_memb_iter_all_first(iter, trps->ctable);
       memb!=NULL;
       memb=tr_comm_memb_iter_all_next(iter)) {
    if (tr_comm_memb_get_origin(memb)==NULL)
      continue; /* do not expire local entries */

    if (tr_comm_memb_is_expired(memb, &sweep_time)) {
      if (tr_comm_memb_get_times_expired(memb)>0) {
        /* Already expired once; flush. */
        tr_debug("trps_sweep_ctable: flushing expired community membership (%.*s in %.*s, origin %.*s, expired %s).",
                 tr_comm_memb_get_realm_id(memb)->len, tr_comm_memb_get_realm_id(memb)->buf,
                 tr_comm_get_id(tr_comm_memb_get_comm(memb))->len, tr_comm_get_id(tr_comm_memb_get_comm(memb))->buf,
                 tr_comm_memb_get_origin(memb)->len, tr_comm_memb_get_origin(memb)->buf,
                 timespec_to_str(tr_comm_memb_get_expiry(memb)));
        tr_comm_table_remove_memb(trps->ctable, memb);
        tr_comm_memb_free(memb);
      } else {
        /* This is the first expiration. Note this and reset the expiry time. */
        tr_comm_memb_expire(memb);
        trps_compute_expiry(trps, tr_comm_memb_get_interval(memb), tr_comm_memb_get_expiry(memb));
        tr_debug("trps_sweep_ctable: community membership expired at %s, resetting expiry to %s (%.*s in %.*s, origin %.*s).",
                 timespec_to_str(&sweep_time),
                 timespec_to_str(tr_comm_memb_get_expiry(memb)),
                 tr_comm_memb_get_realm_id(memb)->len, tr_comm_memb_get_realm_id(memb)->buf,
                 tr_comm_get_id(tr_comm_memb_get_comm(memb))->len, tr_comm_get_id(tr_comm_memb_get_comm(memb))->buf,
                 tr_comm_memb_get_origin(memb)->len, tr_comm_memb_get_origin(memb)->buf);
      }
    }
  }

  /* get rid of any unreferenced realms, etc */
  tr_comm_table_sweep(trps->ctable);

cleanup:
  talloc_free(tmp_ctx);
  return rc;
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
    if ((trp_inforec_set_trust_router(rec, trp_route_dup_trust_router(route)) != TRP_SUCCESS)
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

static TRP_UPD *trps_route_to_upd(TALLOC_CTX *mem_ctx, TRPS_INSTANCE *trps, TRP_ROUTE *route)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_UPD *upd=trp_upd_new(tmp_ctx);
  TRP_INFOREC *rec=NULL;

  if (upd==NULL) {
    tr_err("trps_route_to_upd: could not create update message.");
    goto cleanup;
  }
  trp_upd_set_realm(upd, trp_route_dup_realm(route));
  if (trp_upd_get_realm(upd)==NULL) {
    tr_err("trps_route_to_upd: could not copy realm.");
    upd=NULL; /* it's still in tmp_ctx, so it will be freed */
    goto cleanup;
  }
  trp_upd_set_comm(upd, trp_route_dup_comm(route));
  if (trp_upd_get_comm(upd)==NULL) {
    tr_err("trps_route_to_upd: could not copy comm.");
    upd=NULL; /* it's still in tmp_ctx, so it will be freed */
    goto cleanup;
  }
  rec=trps_route_to_inforec(tmp_ctx, trps, route);
  if (rec==NULL) {
    tr_err("trps_route_to_upd: could not create route info record for realm %.*s in comm %.*s.",
           trp_route_get_realm(route)->len, trp_route_get_realm(route)->buf,
           trp_route_get_comm(route)->len, trp_route_get_comm(route)->buf);
    upd=NULL; /* it's till in tmp_ctx, so it will be freed */
    goto cleanup;
  }
  trp_upd_add_inforec(upd, rec);

  /* sucess */
  talloc_steal(mem_ctx, upd);

cleanup:
  talloc_free(tmp_ctx);
  return upd;
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

/* Add TRP_UPD msgs to the updates GPtrArray. Caller needs to arrange for these to be freed. */
static TRP_RC trps_select_route_updates_for_peer(TALLOC_CTX *mem_ctx,
                                                 GPtrArray *updates,
                                                 TRPS_INSTANCE *trps,
                                                 TR_NAME *peer_gssname,
                                                 int triggered)
{
  size_t n_comm=0;
  TR_NAME **comm=trp_rtable_get_comms(trps->rtable, &n_comm);
  TR_NAME **realm=NULL;
  size_t n_realm=0;
  size_t ii=0, jj=0;
  TRP_ROUTE *best=NULL;
  TRP_UPD *upd=NULL;

  if (updates==NULL)
    return TRP_BADARG;

  for (ii=0; ii<n_comm; ii++) {
    realm=trp_rtable_get_comm_realms(trps->rtable, comm[ii], &n_realm);
    for (jj=0; jj<n_realm; jj++) {
      best=trps_select_realm_update(trps, comm[ii], realm[jj], peer_gssname);
      /* If we found a route, add it to the list. If triggered!=0, then only
       * add triggered routes. */
      if ((best!=NULL) && ((!triggered) || trp_route_is_triggered(best))) {
        upd=trps_route_to_upd(mem_ctx, trps, best);
        if (upd==NULL) {
          tr_err("trps_select_route_updates_for_peer: unable to create update message.");
          continue;
        }
        g_ptr_array_add(updates, upd);
      }
    }
    
    if (realm!=NULL)
      talloc_free(realm);
    realm=NULL;
    n_realm=0;
  }

  if (comm!=NULL)
    talloc_free(comm);
  
  return TRP_SUCCESS;
}

static TRP_INFOREC *trps_memb_to_inforec(TALLOC_CTX *mem_ctx, TRPS_INSTANCE *trps, TR_COMM_MEMB *memb)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_INFOREC *rec=NULL;
  TR_COMM *comm=NULL;

  if (memb==NULL)
    goto cleanup;

  comm=tr_comm_memb_get_comm(memb);
  rec=trp_inforec_new(tmp_ctx, TRP_INFOREC_TYPE_COMMUNITY);
  if (rec==NULL)
    goto cleanup;
  
  if (TRP_SUCCESS!=trp_inforec_set_comm_type(rec, tr_comm_get_type(comm))) {
    rec=NULL;
    goto cleanup;
  }
  
  if (TRP_SUCCESS!=trp_inforec_set_role(rec, tr_comm_memb_get_role(memb))) {
    rec=NULL;
    goto cleanup;
  }

  if ((NULL!=tr_comm_get_apcs(comm)) &&
      ( (TRP_SUCCESS!=trp_inforec_set_apcs(rec,
                                           tr_apc_dup(rec, tr_comm_get_apcs(comm)))) ||
        (NULL==trp_inforec_get_apcs(rec)))) {
    rec=NULL;
    goto cleanup;
  }

  if ((NULL!=tr_comm_get_owner_realm(comm)) &&
      ( (TRP_SUCCESS!=trp_inforec_set_owner_realm(rec, tr_dup_name(tr_comm_get_owner_realm(comm)))) ||
        (NULL==trp_inforec_get_owner_realm(rec)))) {
    rec=NULL;
    goto cleanup;
  }

  if ((NULL!=tr_comm_get_owner_contact(comm)) &&
      ( (TRP_SUCCESS!=trp_inforec_set_owner_contact(rec, tr_dup_name(tr_comm_get_owner_contact(comm)))) ||
        (NULL==trp_inforec_get_owner_contact(rec)))) {
    rec=NULL;
    goto cleanup;
  }

  if ((NULL!=tr_comm_memb_get_provenance(memb)) &&
      (TRP_SUCCESS!=trp_inforec_set_provenance(rec, tr_comm_memb_get_provenance(memb)))) {
    rec=NULL;
    goto cleanup;
  }

  if (TRP_SUCCESS!=trp_inforec_set_interval(rec, trps_get_update_interval(trps))) {
    rec=NULL;
    goto cleanup;
  }

  /* success! */
  talloc_steal(mem_ctx, rec);

cleanup:
  talloc_free(tmp_ctx);
  return rec;
}

/* construct an update with all the inforecs for comm/realm/role to be sent to peer */
static TRP_UPD *trps_comm_update(TALLOC_CTX *mem_ctx, TRPS_INSTANCE *trps, TR_NAME *peer_gssname, TR_COMM *comm, TR_REALM *realm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_UPD *upd=trp_upd_new(tmp_ctx);
  TRP_INFOREC *rec=NULL;
  TR_COMM_ITER *iter=NULL;
  TR_COMM_MEMB *memb=NULL;

  if (upd==NULL)
    goto cleanup;
  
  trp_upd_set_comm(upd, tr_comm_dup_id(comm));
  trp_upd_set_realm(upd, tr_realm_dup_id(realm));
  /* leave peer empty */

  iter=tr_comm_iter_new(tmp_ctx);
  if (iter==NULL) {
    tr_err("trps_comm_update: unable to allocate iterator.");
    upd=NULL;
    goto cleanup;
  }
  
  /* now add inforecs */
  switch (realm->role) {
  case TR_ROLE_IDP:
    memb=tr_comm_table_find_idp_memb(trps->ctable,
                                     tr_realm_get_id(realm),
                                     tr_comm_get_id(comm));
    break;
  case TR_ROLE_RP:
    memb=tr_comm_table_find_rp_memb(trps->ctable,
                                    tr_realm_get_id(realm),
                                    tr_comm_get_id(comm));
    break;
  default:
    break;
  }
  if (memb!=NULL) {
    for (memb=tr_comm_memb_iter_first(iter, memb);
         memb!=NULL;
         memb=tr_comm_memb_iter_next(iter)) {
      rec=trps_memb_to_inforec(tmp_ctx, trps, memb);
      if (rec==NULL) {
        tr_err("trps_comm_update: unable to allocate inforec.");
        upd=NULL;
        goto cleanup;
      }
      trp_upd_add_inforec(upd, rec);
    }
  }

  if (trp_upd_get_inforec(upd)==NULL)
    upd=NULL; /* no inforecs, no reason to send the update */
  else
    talloc_steal(mem_ctx, upd); /* success! */

cleanup:
  talloc_free(tmp_ctx);
  return upd;
}

/* Find all community updates to send to a peer and add these as TR_UPD records
 * to the updates GPtrArray. */
static TRP_RC trps_select_comm_updates_for_peer(TALLOC_CTX *mem_ctx,
                                                GPtrArray *updates,
                                                TRPS_INSTANCE *trps,
                                                TR_NAME *peer_gssname,
                                                int triggered)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM_ITER *comm_iter=NULL;
  TR_COMM *comm=NULL;
  TR_COMM_ITER *realm_iter=NULL;
  TR_REALM *realm=NULL;
  TRP_UPD *upd=NULL;
  TRP_RC rc=TRP_ERROR;

  /* currently do not send any communities on triggered updates */
  if (triggered) {
    rc=TRP_SUCCESS;
    goto cleanup;
  }

  comm_iter=tr_comm_iter_new(tmp_ctx);
  realm_iter=tr_comm_iter_new(tmp_ctx);
  if ((comm_iter==NULL) || (realm_iter==NULL)) {
    tr_err("trps_select_comm_updates_for_peer: unable to allocate iterator.");
    rc=TRP_NOMEM;
    goto cleanup;
  }

  /* do every community */
  for (comm=tr_comm_table_iter_first(comm_iter, trps->ctable);
       comm!=NULL;
       comm=tr_comm_table_iter_next(comm_iter)) {
    /* do every realm in this community */
    tr_debug("trps_select_comm_updates_for_peer: looking through community %.*s",
             tr_comm_get_id(comm)->len,
             tr_comm_get_id(comm)->buf);
    for (realm=tr_realm_iter_first(realm_iter, trps->ctable, tr_comm_get_id(comm));
         realm!=NULL;
         realm=tr_realm_iter_next(realm_iter)) {
      /* get the update for this comm/realm */
      tr_debug("trps_select_comm_updates_for_peer: adding realm %.*s",
               tr_realm_get_id(realm)->len,
               tr_realm_get_id(realm)->buf);
      upd=trps_comm_update(mem_ctx, trps, peer_gssname, comm, realm);
      if (upd!=NULL)
        g_ptr_array_add(updates, upd);
    }
  }

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

/**
 * Filter the inforecs in a single update
 *
 * @param filt The filter to apply
 * @param upd The update to filter
 */
static void trps_filter_one_outbound_update(TR_FILTER *filt, TRP_UPD *upd)
{
  TRP_INFOREC *this=NULL, *next=NULL;
  TR_FILTER_ACTION action=TR_FILTER_ACTION_REJECT;

  for(this=trp_upd_get_inforec(upd); this!=NULL; this=next) {
    next=this->next;
    if ((TR_FILTER_NO_MATCH==tr_filter_apply(this, filt, NULL, &action))
        || (action!=TR_FILTER_ACTION_ACCEPT)) {
      /* Either no filter matched or one matched and rejected this record */
      trp_upd_remove_inforec(upd, this); /* "this" is now invalid */
    }
  }
}

/**
 * May shuffle the update list.
 *
 * @param filters The filter set for the relevant TRP peer
 * @param updates GPtrArray of updates to filter
 */
static void trps_filter_outbound_updates(TR_FILTER_SET *filters, GPtrArray *updates)
{
  TRP_UPD *upd=NULL;
  int ii=0;

  /* walk backward through the array so we can remove elements */
  for (ii=updates->len-1; ii>=0; ii--) {
    upd=g_ptr_array_index(updates, ii);
    trps_filter_one_outbound_update(tr_filter_set_get(filters, TR_FILTER_TYPE_TRP_OUTBOUND), upd);
    /* see if we removed all the records from this update */
    if (trp_upd_num_inforecs(upd)==0)
      g_ptr_array_remove_index_fast(updates, ii); /* does not preserve order at index ii or higher */
  }
}

/* helper for trps_update_one_peer. Frees the TRP_UPD pointed to by a GPtrArray element */
static void trps_trp_upd_destroy(gpointer data)
{
  trp_upd_free((TRP_UPD *)data);
}

/* all routes/communities to a single peer, unless comm/realm are specified (both or neither must be NULL) */
static TRP_RC trps_update_one_peer(TRPS_INSTANCE *trps,
                                   TRP_PEER *peer,
                                   TRP_UPDATE_TYPE update_type,
                                   TR_NAME *comm,
                                   TR_NAME *realm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_MSG msg; /* not a pointer! */
  TRP_UPD *upd=NULL;
  TRP_ROUTE *route=NULL;
  size_t ii=0;
  char *encoded=NULL;
  TRP_RC rc=TRP_ERROR;
  TR_NAME *peer_label=trp_peer_get_label(peer);
  GPtrArray *updates=g_ptr_array_new_with_free_func(trps_trp_upd_destroy);

  if (updates==NULL) {
    tr_err("trps_update_one_peer: unable to allocate updates array.");
    rc=TRP_NOMEM;
    goto cleanup;
  }

  switch (update_type) {
  case TRP_UPDATE_TRIGGERED:
    tr_debug("trps_update_one_peer: preparing triggered update for %.*s",
             peer_label->len, peer_label->buf);
    break;
  case TRP_UPDATE_SCHEDULED:
    tr_debug("trps_update_one_peer: preparing scheduled update for %.*s",
             peer_label->len, peer_label->buf);
    break;
  case TRP_UPDATE_REQUESTED:
    tr_debug("trps_update_one_peer: preparing requested update for %.*s",
             peer_label->len, peer_label->buf);
    break;
  default:
    tr_err("trps_update_one_peer: invalid update type requested.");
    rc=TRP_BADARG;
    goto cleanup;
  }

  /* First, gather route updates. */
  tr_debug("trps_update_one_peer: selecting route updates for %.*s.", peer_label->len, peer_label->buf);
  if ((comm==NULL) && (realm==NULL)) {
    /* do all realms */
    rc=trps_select_route_updates_for_peer(tmp_ctx,
                                          updates,
                                          trps,
                                          peer_label,
                                          update_type==TRP_UPDATE_TRIGGERED);
  } else if ((comm!=NULL) && (realm!=NULL)) {
    /* a single community/realm was requested */
    route=trps_select_realm_update(trps, comm, realm, peer_label);
    if (route==NULL) {
      /* we have no actual update to send back, MUST send a retraction */
      tr_debug("trps_update_one_peer: community/realm without route requested, sending mandatory retraction.");
      route=trp_route_new(tmp_ctx);
      trp_route_set_comm(route, tr_dup_name(comm));
      trp_route_set_realm(route, tr_dup_name(realm));
      trp_route_set_peer(route, tr_new_name(""));
      trp_route_set_metric(route, TRP_METRIC_INFINITY);
      trp_route_set_trust_router(route, tr_new_name(""));
      trp_route_set_next_hop(route, tr_new_name(""));
    }
    upd=trps_route_to_upd(tmp_ctx, trps, route);
    if (upd==NULL) {
      tr_err("trps_update_one_peer: unable to allocate route update.");
      rc=TRP_NOMEM;
      goto cleanup;
    }
    g_ptr_array_add(updates, upd);
  } else {
    tr_err("trps_update_one_peer: error: only comm or realm was specified. Need both or neither.");
    rc=TRP_ERROR;
    goto cleanup;
  }

  /* Second, gather community updates */
  tr_debug("trps_update_one_peer: selecting community updates for %.*s.", peer_label->len, peer_label->buf);
  rc=trps_select_comm_updates_for_peer(tmp_ctx, updates, trps, peer_label, update_type==TRP_UPDATE_TRIGGERED);

  /* see if we have anything to send */
  if (updates->len<=0)
    tr_debug("trps_update_one_peer: no updates for %.*s", peer_label->len, peer_label->buf);
  else {
    /* Apply outbound TRP filters for this peer */
    trps_filter_outbound_updates(peer->filters, updates);

    if (updates->len<=0)
      tr_debug("trps_update_one_peer: no updates for %.*s after filtering.", peer_label->len, peer_label->buf);
    else {
      tr_debug("trps_update_one_peer: sending %d update messages.", updates->len);
      for (ii=0; ii<updates->len; ii++) {
        upd = (TRP_UPD *) g_ptr_array_index(updates, ii);
        /* now encode the update message */
        tr_msg_set_trp_upd(&msg, upd);
        encoded = tr_msg_encode(&msg);
        if (encoded == NULL) {
          tr_err("trps_update_one_peer: error encoding update.");
          rc = TRP_ERROR;
          goto cleanup;
        }

        tr_debug("trps_update_one_peer: adding message to queue.");
        if (trps_send_msg(trps, peer, encoded) != TRP_SUCCESS)
          tr_err("trps_update_one_peer: error queueing update.");
        else
          tr_debug("trps_update_one_peer: update queued successfully.");

        tr_msg_free_encoded(encoded);
        encoded = NULL;
      }
    }
  }

  rc=TRP_SUCCESS;

cleanup:
  if (updates!=NULL)
    g_ptr_array_free(updates, TRUE); /* frees any TRP_UPD records */
  talloc_free(tmp_ctx);
  return rc;
}

/* all routes/communities to all peers */
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
       (peer!=NULL) && (rc==TRP_SUCCESS);
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

  tr_debug("trps_update: rc=%u after attempting update.", rc);
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
