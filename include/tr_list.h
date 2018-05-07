/*
 * Copyright (c) 2018 JANET(UK)
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

#ifndef TRUST_ROUTER_TR_LIST_H
#define TRUST_ROUTER_TR_LIST_H

#include <talloc.h>
#include <glib.h>

typedef GPtrArray *TR_LIST;

typedef void (TR_LIST_FOREACH_FUNC)(void *item, void *cookie);

typedef struct tr_list_iter{
  TR_LIST *list;
  guint index;
} TR_LIST_ITER;

#define tr_list_index(LIST, INDEX) (g_ptr_array_index(*(LIST),(INDEX)))
#define tr_list_length(LIST) ((size_t)((*(LIST))->len))

TR_LIST *tr_list_new(TALLOC_CTX *mem_ctx);
void tr_list_free(TR_LIST *list);
void *tr_list_add(TR_LIST *list, void *item, int steal);

TR_LIST_ITER *tr_list_iter_new(TALLOC_CTX *mem_ctx);
void tr_list_iter_free(TR_LIST_ITER *iter);
void *tr_list_iter_first(TR_LIST_ITER *iter, TR_LIST *list);
void *tr_list_iter_next(TR_LIST_ITER *iter);
void tr_list_foreach(TR_LIST *list, TR_LIST_FOREACH_FUNC *func, void *cookie);

#endif //TRUST_ROUTER_TR_LIST_H
