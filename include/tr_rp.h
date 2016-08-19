/*
 * Copyright (c) 2012, JANET(UK)
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

#ifndef TR_RP_H
#define TR_RP_H

#include <talloc.h>

#include <tr_filter.h>

#define TR_MAX_GSS_NAMES 5

typedef struct tr_rp_client {
  struct tr_rp_client *next;
  struct tr_rp_client *comm_next;
  TR_NAME *gss_names[TR_MAX_GSS_NAMES];
  TR_FILTER *filter;
} TR_RP_CLIENT;

/* Structure to make a linked list of RP realms by name for community config */
typedef struct tr_rp_realm {
  struct tr_rp_realm *next;
  TR_NAME *realm_name;
} TR_RP_REALM;

/* prototypes */
TR_RP_CLIENT *tr_rp_client_new(TALLOC_CTX *mem_ctx);
void tr_rp_client_free(TR_RP_CLIENT *client);
TR_RP_CLIENT *tr_rp_client_add(TR_RP_CLIENT *clients, TR_RP_CLIENT *new);
int tr_rp_client_add_gss_name(TR_RP_CLIENT *client, TR_NAME *name);
int tr_rp_client_set_filter(TR_RP_CLIENT *client, TR_FILTER *filt);

TR_RP_CLIENT *tr_rp_client_lookup(TR_RP_CLIENT *rp_clients, TR_NAME *gss_name);
TR_RP_REALM *tr_rp_realm_add(TR_RP_REALM *head, TR_RP_REALM *new);
#endif
