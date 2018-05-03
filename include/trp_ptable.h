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

#ifndef _TRP_PTABLE_H_
#define _TRP_PTABLE_H_

#include <time.h>
#include <talloc.h>

#include <tr_name_internal.h>
#include <tr_gss_names.h>
#include <trust_router/trp.h>
#include <tr_filter.h>
#include <trp_peer.h>

typedef struct trp_ptable {
  TRP_PEER *head; /* head of a peer table list */
} TRP_PTABLE;

/* iterator for the peer table */
typedef TRP_PEER *TRP_PTABLE_ITER;

TRP_PTABLE *trp_ptable_new(TALLOC_CTX *memctx);
void trp_ptable_free(TRP_PTABLE *ptbl);
TRP_RC trp_ptable_add(TRP_PTABLE *ptbl, TRP_PEER *newpeer);
TRP_RC trp_ptable_remove(TRP_PTABLE *ptbl, TRP_PEER *peer);
TRP_PEER *trp_ptable_find_gss_name(TRP_PTABLE *ptbl, TR_NAME *gssname);
TRP_PEER *trp_ptable_find_servicename(TRP_PTABLE *ptbl, TR_NAME *servicename);

TRP_PTABLE_ITER *trp_ptable_iter_new(TALLOC_CTX *mem_ctx);
TRP_PEER *trp_ptable_iter_first(TRP_PTABLE_ITER *iter, TRP_PTABLE *ptbl);
TRP_PEER *trp_ptable_iter_next(TRP_PTABLE_ITER *iter);
void trp_ptable_iter_free(TRP_PTABLE_ITER *iter);

/* trp_ptable_encoders.c */
char *trp_ptable_to_str(TALLOC_CTX *memctx, TRP_PTABLE *ptbl, const char *sep, const char *lineterm);
json_t *trp_ptable_to_json(TRP_PTABLE *ptbl);

#endif /* _TRP_PTABLE_H_ */
