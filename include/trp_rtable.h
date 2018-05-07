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

#include <trp_route.h>
#include <trp_internal.h>


typedef GHashTable TRP_RTABLE;

/* trp_rtable.c */
TRP_RTABLE *trp_rtable_new(void);
void trp_rtable_free(TRP_RTABLE *rtbl);
void trp_rtable_add(TRP_RTABLE *rtbl, TRP_ROUTE *entry); /* adds or updates */
void trp_rtable_remove(TRP_RTABLE *rtbl, TRP_ROUTE *entry);
void trp_rtable_clear(TRP_RTABLE *rtbl);
size_t trp_rtable_size(TRP_RTABLE *rtbl);
size_t trp_rtable_comm_size(TRP_RTABLE *rtbl, TR_NAME *comm);
size_t trp_rtable_realm_size(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm);
TRP_ROUTE **trp_rtable_get_entries(TALLOC_CTX *mem_ctx, TRP_RTABLE *rtbl, size_t *n_out);
TR_NAME **trp_rtable_get_comms(TRP_RTABLE *rtbl, size_t *n_out);
TRP_ROUTE **trp_rtable_get_comm_entries(TRP_RTABLE *rtbl, TR_NAME *comm, size_t *n_out);
TR_NAME **trp_rtable_get_comm_realms(TRP_RTABLE *rtbl, TR_NAME *comm, size_t *n_out);
TRP_ROUTE **trp_rtable_get_realm_entries(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, size_t *n_out);
TR_NAME **trp_rtable_get_comm_realm_peers(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, size_t *n_out);
TRP_ROUTE *trp_rtable_get_entry(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer);
TRP_ROUTE *trp_rtable_get_selected_entry(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm);
void trp_rtable_clear_triggered(TRP_RTABLE *rtbl);

/* trp_rtable_encoders.c */
char *trp_rtable_to_str(TALLOC_CTX *mem_ctx, TRP_RTABLE *rtbl, const char *sep, const char *lineterm);
json_t *trp_rtable_to_json(TRP_RTABLE *rtbl);

#endif /* _TRP_RTABLE_H_ */
