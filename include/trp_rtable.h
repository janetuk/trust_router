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

#ifndef _TRP_RTABLE_H_
#define _TRP_RTABLE_H_

#include <glib.h>
#include <talloc.h>
#include <time.h>

#include <trp_internal.h>

typedef struct trp_route {
  TR_NAME *comm;
  TR_NAME *realm;
  TR_NAME *peer;
  unsigned int metric;
  TR_NAME *trust_router; /* hostname */
  unsigned int trp_port;
  unsigned int tid_port;
  TR_NAME *next_hop;
  int selected;
  unsigned int interval; /* interval from route update */
  struct timespec *expiry;
  int local; /* is this a local route? */
  int triggered;
} TRP_ROUTE;

typedef GHashTable TRP_RTABLE;

TRP_RTABLE *trp_rtable_new(void);
void trp_rtable_free(TRP_RTABLE *rtbl);
void trp_rtable_add(TRP_RTABLE *rtbl, TRP_ROUTE *entry); /* adds or updates */
void trp_rtable_remove(TRP_RTABLE *rtbl, TRP_ROUTE *entry);
void trp_rtable_clear(TRP_RTABLE *rtbl);
size_t trp_rtable_size(TRP_RTABLE *rtbl);
size_t trp_rtable_comm_size(TRP_RTABLE *rtbl, TR_NAME *comm);
size_t trp_rtable_realm_size(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm);
TRP_ROUTE **trp_rtable_get_entries(TRP_RTABLE *rtbl, size_t *n_out);
TR_NAME **trp_rtable_get_comms(TRP_RTABLE *rtbl, size_t *n_out);
TRP_ROUTE **trp_rtable_get_comm_entries(TRP_RTABLE *rtbl, TR_NAME *comm, size_t *n_out);
TR_NAME **trp_rtable_get_comm_realms(TRP_RTABLE *rtbl, TR_NAME *comm, size_t *n_out);
TRP_ROUTE **trp_rtable_get_realm_entries(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, size_t *n_out);
TR_NAME **trp_rtable_get_comm_realm_peers(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, size_t *n_out);
TRP_ROUTE *trp_rtable_get_entry(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer);
TRP_ROUTE *trp_rtable_get_selected_entry(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm);
void trp_rtable_clear_triggered(TRP_RTABLE *rtbl);
char *trp_rtable_to_str(TALLOC_CTX *mem_ctx, TRP_RTABLE *rtbl, const char *sep, const char *lineterm);

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
void trp_route_set_peer(TRP_ROUTE *entry, TR_NAME *peer);
TR_NAME *trp_route_get_peer(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_peer(TRP_ROUTE *entry);
void trp_route_set_metric(TRP_ROUTE *entry, unsigned int metric);
unsigned int trp_route_get_metric(TRP_ROUTE *entry);
void trp_route_set_next_hop(TRP_ROUTE *entry, TR_NAME *next_hop);
TR_NAME *trp_route_get_next_hop(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_next_hop(TRP_ROUTE *entry);
void trp_route_set_selected(TRP_ROUTE *entry, int sel);
int trp_route_is_selected(TRP_ROUTE *entry);
void trp_route_set_interval(TRP_ROUTE *entry, int interval);
int trp_route_get_interval(TRP_ROUTE *entry);
void trp_route_set_expiry(TRP_ROUTE *entry, struct timespec *exp);
struct timespec *trp_route_get_expiry(TRP_ROUTE *entry);
void trp_route_set_local(TRP_ROUTE *entry, int local);
int trp_route_is_local(TRP_ROUTE *entry);
void trp_route_set_triggered(TRP_ROUTE *entry, int trig);
int trp_route_is_triggered(TRP_ROUTE *entry);
char *trp_route_to_str(TALLOC_CTX *mem_ctx, TRP_ROUTE *entry, const char *sep);

#endif /* _TRP_RTABLE_H_ */
