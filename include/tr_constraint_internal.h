/*
 * Copyright (c) 2018, JANET(UK)
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


#ifndef TRUST_ROUTER_TR_CONSTRAINT_INTERNAL_H
#define TRUST_ROUTER_TR_CONSTRAINT_INTERNAL_H

#include <talloc.h>

#include <tr_list.h>
#include <tr_name_internal.h>
#include <trust_router/tr_constraint.h>


struct tr_constraint {
  TR_NAME *type;
  TR_LIST *matches;
};

TR_CONSTRAINT *tr_constraint_new(TALLOC_CTX *mem_ctx);
void tr_constraint_free(TR_CONSTRAINT *cons);
TR_CONSTRAINT *tr_constraint_dup(TALLOC_CTX *mem_ctx, TR_CONSTRAINT *cons);

/* Iterator for TR_CONS matches */
typedef TR_LIST_ITER TR_CONSTRAINT_ITER;
#define tr_constraint_iter_new(CTX) (tr_list_iter_new(CTX))
#define tr_constraint_iter_free(ITER) (tr_list_iter_free(ITER))
#define tr_constraint_iter_first(ITER, CONS) ((TR_NAME *) tr_list_iter_first((ITER), (CONS)->matches))
#define tr_constraint_iter_next(ITER) ((TR_NAME *) tr_list_iter_next(ITER))
#define tr_constraint_add_match(CONS, MATCH) ((TR_NAME *) tr_list_add((CONS)->matches, (MATCH), 0))

#endif //TRUST_ROUTER_TR_CONSTRAINT_INTERNAL_H
