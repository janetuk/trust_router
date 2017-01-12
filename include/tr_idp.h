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

#ifndef TR_IDP_H
#define TR_IDP_H

#include <talloc.h>
#include <time.h>

#include <trust_router/tr_name.h>
#include <tr_apc.h>

typedef struct tr_aaa_server {
  struct tr_aaa_server *next;
  TR_NAME *hostname;
} TR_AAA_SERVER;

typedef struct tr_aaa_server_iter {
  TR_AAA_SERVER *this;
} TR_AAA_SERVER_ITER;

/* may also want to use in tr_rp.h */
typedef enum tr_realm_origin {
  TR_REALM_LOCAL=0, /* realm we were configured to contact */
  TR_REALM_REMOTE_INCOMPLETE, /* realm we were configured to know about, without contact info yet */
  TR_REALM_REMOTE, /* realm we were configured to know about, with discovered contact info */
  TR_REALM_DISCOVERED /* realm we learned about from a peer */
} TR_REALM_ORIGIN;

typedef struct tr_idp_realm {
  struct tr_idp_realm *next;
  struct tr_idp_realm *comm_next; /* for linked list in comm config */
  TR_NAME *realm_id;
  int shared_config;
  TR_AAA_SERVER *aaa_servers;
  TR_APC *apcs;
  TR_REALM_ORIGIN origin; /* how did we learn about this realm? */
  unsigned int refcount; /* how many TR_COMM_MEMBs refer to this realm */
} TR_IDP_REALM;
  
TR_IDP_REALM *tr_idp_realm_new(TALLOC_CTX *mem_ctx);
void tr_idp_realm_free(TR_IDP_REALM *idp);
TR_NAME *tr_idp_realm_get_id(TR_IDP_REALM *idp);
TR_NAME *tr_idp_realm_dup_id(TR_IDP_REALM *idp);
void tr_idp_realm_set_id(TR_IDP_REALM *idp, TR_NAME *id);
void tr_idp_realm_set_apcs(TR_IDP_REALM *idp, TR_APC *apc);
TR_APC *tr_idp_realm_get_apcs(TR_IDP_REALM *idp);
TR_IDP_REALM *tr_idp_realm_lookup(TR_IDP_REALM *idp_realms, TR_NAME *idp_name);
TR_IDP_REALM *tr_idp_realm_add_func(TR_IDP_REALM *head, TR_IDP_REALM *new);
#define tr_idp_realm_add(head,new) ((head)=tr_idp_realm_add_func((head),(new)))
TR_IDP_REALM *tr_idp_realm_remove_func(TR_IDP_REALM *head, TR_IDP_REALM *remove);
#define tr_idp_realm_remove(head,remove) ((head)=tr_idp_realm_remove_func((head),(remove)))
TR_IDP_REALM *tr_idp_realm_sweep_func(TR_IDP_REALM *head);
#define tr_idp_realm_sweep(head) ((head)=tr_idp_realm_sweep_func((head)))
char *tr_idp_realm_to_str(TALLOC_CTX *mem_ctx, TR_IDP_REALM *idp);
void tr_idp_realm_incref(TR_IDP_REALM *realm);
void tr_idp_realm_decref(TR_IDP_REALM *realm);

TR_AAA_SERVER *tr_aaa_server_new(TALLOC_CTX *mem_ctx, TR_NAME *hostname);
void tr_aaa_server_free(TR_AAA_SERVER *aaa);

TR_AAA_SERVER_ITER *tr_aaa_server_iter_new(TALLOC_CTX *mem_ctx);
void tr_aaa_server_iter_free(TR_AAA_SERVER_ITER *iter);
TR_AAA_SERVER *tr_aaa_server_iter_first(TR_AAA_SERVER_ITER *iter, TR_AAA_SERVER *aaa);
TR_AAA_SERVER *tr_aaa_server_iter_next(TR_AAA_SERVER_ITER *iter);

TR_AAA_SERVER *tr_idp_aaa_server_lookup(TR_IDP_REALM *idp_realms, TR_NAME *idp_realm_name, TR_NAME *comm, int *shared_out);
TR_AAA_SERVER *tr_default_server_lookup(TR_AAA_SERVER *default_servers, TR_NAME *comm);

#endif
