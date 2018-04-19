/*
 * Copyright (c) 2012-2018, JANET(UK)
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

#ifndef TRUST_ROUTER_TR_RP_CLIENT_H
#define TRUST_ROUTER_TR_RP_CLIENT_H

#include <talloc.h>

#include <tr_gss_names.h>
#include <tr_filter.h>

typedef struct tr_rp_client {
  struct tr_rp_client *next;
  struct tr_rp_client *comm_next;
  TR_GSS_NAMES *gss_names;
  TR_FILTER_SET *filters;
} TR_RP_CLIENT;

typedef struct tr_rp_client *TR_RP_CLIENT_ITER;

/* tr_rp_client.c */
TR_RP_CLIENT *tr_rp_client_new(TALLOC_CTX *mem_ctx);
void tr_rp_client_free(TR_RP_CLIENT *client);
TR_RP_CLIENT *tr_rp_client_add_func(TR_RP_CLIENT *clients, TR_RP_CLIENT *new);
#define tr_rp_client_add(clients,new) ((clients)=tr_rp_client_add_func((clients),(new)))
int tr_rp_client_add_gss_name(TR_RP_CLIENT *client, TR_NAME *name);
int tr_rp_client_set_filters(TR_RP_CLIENT *client, TR_FILTER_SET *filts);
TR_RP_CLIENT_ITER *tr_rp_client_iter_new(TALLOC_CTX *memctx);
void tr_rp_client_iter_free(TR_RP_CLIENT_ITER *iter);
TR_RP_CLIENT *tr_rp_client_iter_first(TR_RP_CLIENT_ITER *iter, TR_RP_CLIENT *rp_clients);
TR_RP_CLIENT *tr_rp_client_iter_next(TR_RP_CLIENT_ITER *iter);
TR_RP_CLIENT *tr_rp_client_lookup(TR_RP_CLIENT *rp_clients, TR_NAME *gss_name);

/* tr_rp_client_encoders.c */
json_t *tr_rp_clients_to_json(TR_RP_CLIENT *rp_clients);

#endif //TRUST_ROUTER_TR_RP_CLIENT_H
