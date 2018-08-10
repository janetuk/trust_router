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
#include <tr_name_internal.h>

/* Structure to make a linked list of RP realms by name for community config */
typedef struct tr_rp_realm {
  struct tr_rp_realm *next;
  TR_NAME *realm_id;
  unsigned int refcount; /* how many TR_COMM_MEMBs refer to this realm */
} TR_RP_REALM;

/* prototypes */
TR_RP_REALM *tr_rp_realm_new(TALLOC_CTX *mem_ctx);
void tr_rp_realm_free(TR_RP_REALM *rp);
TR_NAME *tr_rp_realm_get_id(TR_RP_REALM *rp);
TR_NAME *tr_rp_realm_dup_id(TR_RP_REALM *rp);
void tr_rp_realm_set_id(TR_RP_REALM *rp, TR_NAME *id);
TR_RP_REALM *tr_rp_realm_lookup(TR_RP_REALM *rp_realms, TR_NAME *rp_name);
TR_RP_REALM *tr_rp_realm_add_func(TR_RP_REALM *head, TR_RP_REALM *new);
#define tr_rp_realm_add(head,new) ((head)=tr_rp_realm_add_func((head),(new)))
TR_RP_REALM *tr_rp_realm_remove_func(TR_RP_REALM *head, TR_RP_REALM *remove);
#define tr_rp_realm_remove(head,remove) ((head)=tr_rp_realm_remove_func((head),(remove)))
TR_RP_REALM *tr_rp_realm_sweep_func(TR_RP_REALM *head);
#define tr_rp_realm_sweep(head) ((head)=tr_rp_realm_sweep_func((head)))
void tr_rp_realm_incref(TR_RP_REALM *realm);
void tr_rp_realm_decref(TR_RP_REALM *realm);

char *tr_rp_realm_to_str(TALLOC_CTX *mem_ctx, TR_RP_REALM *rp);

#endif
