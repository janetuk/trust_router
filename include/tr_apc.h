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

#ifndef TR_APC_H
#define TR_APC_H

#include <talloc.h>

#include <trust_router/tr_name.h>

/* Used to hold lists of APC names in cfg. */
typedef struct tr_apc {
  struct tr_apc *next;
  TR_NAME *id;
} TR_APC;

/* iterator is just a pointer to a TR_APC */
typedef TR_APC *TR_APC_ITER;

TR_APC *tr_apc_new(TALLOC_CTX *mem_ctx);
void tr_apc_free(TR_APC *apc);
TR_APC *tr_apc_add_func(TR_APC *apcs, TR_APC *new);
#define tr_apc_add(apcs,new) ((apcs)=tr_apc_add_func((apcs),(new)))
TR_APC *tr_apc_dup(TALLOC_CTX *mem_ctx, TR_APC *apc);

void tr_apc_set_id(TR_APC *apc, TR_NAME *id);
TR_NAME *tr_apc_get_id(TR_APC *apc);
TR_NAME *tr_apc_dup_id(TR_APC *apc);

char *tr_apc_to_str(TALLOC_CTX *mem_ctx, TR_APC *apc);

TR_APC_ITER *tr_apc_iter_new(TALLOC_CTX *mem_ctx);
TR_APC *tr_apc_iter_first(TR_APC_ITER *iter, TR_APC *apc);
TR_APC *tr_apc_iter_next(TR_APC_ITER *iter);
void tr_apc_iter_free(TR_APC_ITER *iter);

int tr_apc_in_common(TR_APC *one, TR_APC *two);

#endif


