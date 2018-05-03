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

#ifndef TRUST_ROUTER_TRP_PEER_H
#define TRUST_ROUTER_TRP_PEER_H

#include <tr_gss_names.h>
#include <tr_filter.h>

typedef enum trp_peer_conn_status {
  PEER_DISCONNECTED=0,
  PEER_CONNECTED
} TRP_PEER_CONN_STATUS;

typedef struct trp_peer TRP_PEER;
struct trp_peer {
  TRP_PEER *next; /* for making a linked list */
  TR_NAME *label; /* often null, set on first call to trp_peer_get_label or dup_label */
  char *server;
  TR_GSS_NAMES *gss_names;
  TR_NAME *servicename;
  unsigned int port;
  unsigned int linkcost;
  struct timespec last_conn_attempt;
  TRP_PEER_CONN_STATUS outgoing_status;
  TRP_PEER_CONN_STATUS incoming_status;
  void (*conn_status_cb)(TRP_PEER *, void *); /* callback for connected status change */
  void *conn_status_cookie;
  TR_FILTER_SET *filters;
};


TRP_PEER *trp_peer_new(TALLOC_CTX *memctx);
void trp_peer_free(TRP_PEER *peer);
TRP_PEER *trp_peer_tail(TRP_PEER *peer);
TR_NAME *trp_peer_get_label(TRP_PEER *peer);
TR_NAME *trp_peer_dup_label(TRP_PEER *peer);
char *trp_peer_get_server(TRP_PEER *peer);
void trp_peer_set_server(TRP_PEER *peer, const char *server);
void trp_peer_add_gss_name(TRP_PEER *peer, TR_NAME *gssname);
void trp_peer_set_gss_names(TRP_PEER *peer, TR_GSS_NAMES *gss_names);
TR_GSS_NAMES *trp_peer_get_gss_names(TRP_PEER *peer);
TR_NAME *trp_peer_get_servicename(TRP_PEER *peer);
TR_NAME *trp_peer_dup_servicename(TRP_PEER *peer);
unsigned int trp_peer_get_port(TRP_PEER *peer);
void trp_peer_set_port(TRP_PEER *peer, unsigned int port);
unsigned int trp_peer_get_linkcost(TRP_PEER *peer);
struct timespec *trp_peer_get_last_conn_attempt(TRP_PEER *peer);
void trp_peer_set_last_conn_attempt(TRP_PEER *peer, struct timespec *time);
TRP_PEER_CONN_STATUS trp_peer_get_outgoing_status(TRP_PEER *peer);
void trp_peer_set_outgoing_status(TRP_PEER *peer, TRP_PEER_CONN_STATUS status);
TRP_PEER_CONN_STATUS trp_peer_get_incoming_status(TRP_PEER *peer);
void trp_peer_set_incoming_status(TRP_PEER *peer, TRP_PEER_CONN_STATUS status);
int trp_peer_is_connected(TRP_PEER *peer);
void trp_peer_set_linkcost(TRP_PEER *peer, unsigned int linkcost);
void trp_peer_set_conn_status_cb(TRP_PEER *peer, void (*cb)(TRP_PEER *, void *), void *cookie);
void trp_peer_set_filters(TRP_PEER *peer, TR_FILTER_SET *filts);
TR_FILTER *trp_peer_get_filter(TRP_PEER *peer, TR_FILTER_TYPE ftype);

/* trp_peer_encoders.c */
char *trp_peer_to_str(TALLOC_CTX *memctx, TRP_PEER *peer, const char *sep);

#endif //TRUST_ROUTER_TRP_PEER_H
