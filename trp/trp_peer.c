/*
 * Copyright (c) 2016-2018, JANET(UK)
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

#include <time.h>
#include <talloc.h>

#include <tr_name_internal.h>
#include <trp_internal.h>
#include <tr_gss_names.h>
#include <trp_ptable.h>
#include <tr_debug.h>
#include <trp_peer.h>

static int trp_peer_destructor(void *object)
{
  TRP_PEER *peer=talloc_get_type_abort(object, TRP_PEER);
  if (peer->label!=NULL)
    tr_free_name(peer->label);
  if (peer->servicename!=NULL)
    tr_free_name(peer->servicename);
  return 0;
}
TRP_PEER *trp_peer_new(TALLOC_CTX *memctx)
{
  TRP_PEER *peer=talloc(memctx, TRP_PEER);
  if (peer!=NULL) {
    peer->next=NULL;
    peer->label=NULL;
    peer->server=NULL;
    peer->servicename=NULL;
    peer->gss_names=NULL;
    peer->port=0;
    peer->linkcost=TRP_LINKCOST_DEFAULT;
    peer->last_conn_attempt=(struct timespec){0,0};
    peer->outgoing_status=PEER_DISCONNECTED;
    peer->incoming_status=PEER_DISCONNECTED;
    peer->conn_status_cb=NULL;
    peer->conn_status_cookie=NULL;
    peer->filters=NULL;
    talloc_set_destructor((void *)peer, trp_peer_destructor);
  }
  return peer;
}

void trp_peer_free(TRP_PEER *peer)
{
  talloc_free(peer);
}

TRP_PEER *trp_peer_tail(TRP_PEER *peer)
{
  while (peer->next!=NULL) {
    peer=peer->next;
  }
  return peer;
}


/* Get a name that identifies this peer for display to the user, etc.
 * Do not modify or free the label. */
TR_NAME *trp_peer_get_label(TRP_PEER *peer)
{
  char *s=NULL;

  if (peer->label==NULL) {
    s=talloc_asprintf(NULL, "%s:%u", peer->server, peer->port);
    if (s!=NULL) {
      peer->label=tr_new_name(s);
      talloc_free(s);
    }
  }
  return peer->label;
}

/* Get a name that identifies this peer for display to the user, etc.
 * Makes a copy, caller is responsible for freeing.  */
TR_NAME *trp_peer_dup_label(TRP_PEER *peer)
{
  return tr_dup_name(trp_peer_get_label(peer));;
}

char *trp_peer_get_server(TRP_PEER *peer)
{
  return peer->server;
}

static void trp_peer_set_servicename(TRP_PEER *peer, const char *server)
{
  char *name=NULL;
  if (peer->servicename !=NULL)
    tr_free_name(peer->servicename);

  if (server!=NULL)
    name=talloc_asprintf(NULL, "trustrouter/%s", server);

  if (name!=NULL) {
    peer->servicename=tr_new_name(name);
    talloc_free(name);
  } else {
    peer->servicename=NULL;
  }
}

/* copies input; on error, peer->servicename will be null */
void trp_peer_set_server(TRP_PEER *peer, const char *server)
{
  peer->server=talloc_strdup(peer, server); /* will be null on error */
  trp_peer_set_servicename(peer, server);
}

void trp_peer_add_gss_name(TRP_PEER *peer, TR_NAME *gss_name)
{
  if (peer->gss_names==NULL)
    trp_peer_set_gss_names(peer, tr_gss_names_new(peer));
  tr_gss_names_add(peer->gss_names, gss_name);
}

void trp_peer_set_gss_names(TRP_PEER *peer, TR_GSS_NAMES *gss_names)
{
  if (peer->gss_names!=NULL)
    tr_gss_names_free(peer->gss_names);

  peer->gss_names=gss_names;
  talloc_steal(peer, gss_names);
}

/* get the peer gss_names, caller must not free the result */
TR_GSS_NAMES *trp_peer_get_gss_names(TRP_PEER *peer)
{
  return peer->gss_names;
}

/* get the service name (i.e., gssname we see when we connect to this peer) */
TR_NAME *trp_peer_get_servicename(TRP_PEER *peer)
{
  return peer->servicename;
}

/* get a copy of the servicename, caller must free via tr_free_name */
TR_NAME *trp_peer_dup_servicename(TRP_PEER *peer)
{
  return tr_dup_name(peer->servicename);
}

int trp_peer_get_port(TRP_PEER *peer)
{
  return peer->port;
}

void trp_peer_set_port(TRP_PEER *peer, int port)
{
  peer->port=port;
}

unsigned int trp_peer_get_linkcost(TRP_PEER *peer)
{
  if (peer!=NULL)
    return peer->linkcost;
  else
    return 1;
}

void trp_peer_set_linkcost(TRP_PEER *peer, unsigned int linkcost)
{
  if ((linkcost>TRP_METRIC_INFINITY) && (linkcost!=TRP_METRIC_INVALID)) {
    /* This indicates a programming error, but probably means an already infinite metric
     * was (incorrectly) incremented. Issue a warning and proceed with an infinite metric. */
    tr_warning("trp_peer_set_linkcost: link cost > infinity encountered, setting to infinity");
    linkcost=TRP_METRIC_INFINITY;
  }
  peer->linkcost=linkcost;
}

void trp_peer_set_conn_status_cb(TRP_PEER *peer, void (*cb)(TRP_PEER *, void *), void *cookie)
{
  peer->conn_status_cb=cb;
  peer->conn_status_cookie=cookie;
}

/**
 * Set the filter associated with this peer. Any existing filter will be freed. Takes responsibility for
 * freeing the new filter.
 *
 * @param peer Peer to modify
 * @param filts New filter to attach to the peer
 */
void trp_peer_set_filters(TRP_PEER *peer, TR_FILTER_SET *filts)
{
  if (peer->filters!=NULL)
    tr_filter_set_free(peer->filters);

  peer->filters=filts;
  talloc_steal(peer, filts);
}

TR_FILTER *trp_peer_get_filter(TRP_PEER *peer, TR_FILTER_TYPE ftype)
{
  return tr_filter_set_get(peer->filters, ftype);
}

struct timespec *trp_peer_get_last_conn_attempt(TRP_PEER *peer)
{
  return &(peer->last_conn_attempt);
}

void trp_peer_set_last_conn_attempt(TRP_PEER *peer, struct timespec *time)
{
  peer->last_conn_attempt=*time;
}

void trp_peer_set_outgoing_status(TRP_PEER *peer, TRP_PEER_CONN_STATUS status)
{
  TR_NAME *peer_label=trp_peer_get_label(peer);
  int was_connected=trp_peer_is_connected(peer);
  peer->outgoing_status=status;
  tr_debug("trp_peer_set_outgoing_status: %s: status=%d peer connected was %d now %d.",
           peer_label->buf, status, was_connected, trp_peer_is_connected(peer));
  if ((trp_peer_is_connected(peer) != was_connected) && (peer->conn_status_cb!=NULL))
    peer->conn_status_cb(peer, peer->conn_status_cookie);
}

TRP_PEER_CONN_STATUS trp_peer_get_outgoing_status(TRP_PEER *peer)
{
  return peer->outgoing_status;
}

void trp_peer_set_incoming_status(TRP_PEER *peer, TRP_PEER_CONN_STATUS status)
{
  TR_NAME *peer_label=trp_peer_get_label(peer);
  int was_connected=trp_peer_is_connected(peer);
  peer->incoming_status=status;
  tr_debug("trp_peer_set_incoming_status: %s: status=%d peer connected was %d now %d.",
           peer_label->buf, status, was_connected, trp_peer_is_connected(peer));
  if ((trp_peer_is_connected(peer) != was_connected) && (peer->conn_status_cb!=NULL))
    peer->conn_status_cb(peer, peer->conn_status_cookie);
}

TRP_PEER_CONN_STATUS trp_peer_get_incoming_status(TRP_PEER *peer)
{
  return peer->incoming_status;
}

int trp_peer_is_connected(TRP_PEER *peer)
{
  return (peer->outgoing_status==PEER_CONNECTED) && (peer->incoming_status==PEER_CONNECTED);
}
