/*
 * Copyright (c) 2012, 2015, JANET(UK)
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

#ifndef TR_COMM_H
#define TR_COMM_H

#include <tr_idp.h>
#include <tr_rp.h>
#include <tr_apc.h>

typedef enum tr_comm_type {
  TR_COMM_UNKNOWN,
  TR_COMM_APC,
  TR_COMM_COI
} TR_COMM_TYPE;

typedef struct tr_comm {
  struct tr_comm *next;
  TR_NAME *id;
  TR_COMM_TYPE type;
  TR_APC *apcs;
  TR_IDP_REALM *idp_realms;
  TR_RP_REALM *rp_realms;
  time_t expiration_interval; /*Minutes to key expiration; only valid for an APC*/
} TR_COMM;

TR_COMM *tr_comm_new(TALLOC_CTX *mem_ctx);
void tr_comm_free(TR_COMM *comm);
TR_COMM *tr_comm_add(TR_COMM *comms, TR_COMM *new);
void tr_comm_add_idp_realm(TR_COMM *comm, TR_IDP_REALM *realm);
void tr_comm_add_rp_realm(TR_COMM *comm, TR_RP_REALM *realm);
TR_COMM *tr_comm_lookup(TR_COMM *comms, TR_NAME *comm_name);
TR_RP_REALM *tr_find_comm_rp (TR_COMM *comm, TR_NAME *rp_realm);
TR_IDP_REALM *tr_find_comm_idp (TR_COMM *comm, TR_NAME *idp_realm);

#endif
