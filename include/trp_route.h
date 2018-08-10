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


#ifndef TRUST_ROUTER_TRP_ROUTE_H
#define TRUST_ROUTER_TRP_ROUTE_H

typedef struct trp_route {
  TR_NAME *comm;
  TR_NAME *realm;
  TR_NAME *peer;
  unsigned int metric;
  TR_NAME *trust_router; /* hostname */
  int trust_router_port;
  TR_NAME *next_hop;
  int next_hop_port;
  int selected;
  unsigned int interval; /* interval from route update */
  struct timespec *expiry;
  int local; /* is this a local route? */
  int triggered;
} TRP_ROUTE;

/* trp_route.c */
TRP_ROUTE *trp_route_new(TALLOC_CTX *mem_ctx);
void trp_route_free(TRP_ROUTE *entry);
void trp_route_set_comm(TRP_ROUTE *entry, TR_NAME *comm);
TR_NAME *trp_route_get_comm(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_comm(TRP_ROUTE *entry);
void trp_route_set_realm(TRP_ROUTE *entry, TR_NAME *realm);
TR_NAME *trp_route_get_realm(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_realm(TRP_ROUTE *entry);
void trp_route_set_trust_router(TRP_ROUTE *entry, TR_NAME *tr);
TR_NAME *trp_route_get_trust_router(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_trust_router(TRP_ROUTE *entry);
void trp_route_set_trust_router_port(TRP_ROUTE *entry, int port);
int trp_route_get_trust_router_port(TRP_ROUTE *entry);
void trp_route_set_peer(TRP_ROUTE *entry, TR_NAME *peer);
TR_NAME *trp_route_get_peer(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_peer(TRP_ROUTE *entry);
void trp_route_set_metric(TRP_ROUTE *entry, unsigned int metric);
unsigned int trp_route_get_metric(TRP_ROUTE *entry);
void trp_route_set_next_hop(TRP_ROUTE *entry, TR_NAME *next_hop);
TR_NAME *trp_route_get_next_hop(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_next_hop(TRP_ROUTE *entry);
void trp_route_set_next_hop_port(TRP_ROUTE *entry, int port);
int trp_route_get_next_hop_port(TRP_ROUTE *entry);
void trp_route_set_selected(TRP_ROUTE *entry, int sel);
int trp_route_is_selected(TRP_ROUTE *entry);
void trp_route_set_interval(TRP_ROUTE *entry, int interval);
int trp_route_get_interval(TRP_ROUTE *entry);
void trp_route_set_expiry(TRP_ROUTE *entry, struct timespec *exp);
struct timespec *trp_route_get_expiry(TRP_ROUTE *entry);
struct timespec *trp_route_get_expiry_realtime(TRP_ROUTE *comm, struct timespec *result);
void trp_route_set_local(TRP_ROUTE *entry, int local);
int trp_route_is_local(TRP_ROUTE *entry);
void trp_route_set_triggered(TRP_ROUTE *entry, int trig);
int trp_route_is_triggered(TRP_ROUTE *entry);

/* trp_route_encoders.c */
char *trp_route_to_str(TALLOC_CTX *mem_ctx, TRP_ROUTE *entry, const char *sep);
json_t *trp_route_to_json(TRP_ROUTE *route);

#endif //TRUST_ROUTER_TRP_ROUTE_H
