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
#include <talloc.h>
#include <tr_list.h>

static int tr_list_destructor(void *object)
{
  TR_LIST *list = talloc_get_type_abort(object, TR_LIST);
  if (*list)
    g_ptr_array_unref(*list);
  return 0;
}

/* Note that the TR_LIST type is a pointer-to-pointer to
 * a GPtrArray. This is done so that we can hook a talloc destructor
 * to the list to ensure that the GLib reference count is handled correctly
 * when used with talloc. */
TR_LIST *tr_list_new(TALLOC_CTX *mem_ctx)
{
  TR_LIST *list = talloc(mem_ctx, TR_LIST);
  if (list) {
    *list = g_ptr_array_new();
    if (*list == NULL) {
      talloc_free(list);
      return NULL;
    }
    talloc_set_destructor((void *)list, tr_list_destructor);
  }
  return list;
}

void tr_list_free(TR_LIST *list)
{
  talloc_free(list);
}

/**
 * Add an item to the list
 *
 * If steal != 0, performs a talloc_steal() to put the new item in the
 * list's context. If steal == 0, does not do this - in that case, you'll
 * need to be sure that the memory is cleaned up through some other means.
 * (This allows the list to represent non-talloc'ed items.)
 *
 * @param list list to add an item to
 * @param item pointer to the item to add
 * @param steal if non-zero, the item will be added to the list's context with talloc_steal()
 * @return pointer to the added item or null if there was an error
 */
void *tr_list_add(TR_LIST *list, void *item, int steal)
{
  guint old_len = (*list)->len;
  g_ptr_array_add((*list), item);

  if ((*list)->len == old_len)
    return NULL; /* failed to add */

  if (steal)
    talloc_steal(list, item);

  return item;
}

size_t tr_list_length(TR_LIST *list)
{
  return (size_t) (*list)->len;
}

/**
 * Call func(item, cookie) on each item in the list.
 *
 * @param list list to iterate over
 * @param func function, takes two void pointer arguments, first is the item, second the cookie
 * @param cookie
 */
void tr_list_foreach(TR_LIST *list, TR_LIST_FOREACH_FUNC *func, void *cookie)
{
  g_ptr_array_foreach((*list), func, cookie);
}

TR_LIST_ITER *tr_list_iter_new(TALLOC_CTX *mem_ctx)
{
  TR_LIST_ITER *iter = talloc(mem_ctx, TR_LIST_ITER);
  if (iter)
    iter->list = NULL;
  return iter;
}

void tr_list_iter_free(TR_LIST_ITER *iter)
{
  talloc_free(iter);
}

void *tr_list_iter_first(TR_LIST_ITER *iter, TR_LIST *list)
{
  if (!iter || !list || (!(*list)))
    return NULL;

  iter->list = list;
  iter->index = 0;
  return tr_list_iter_next(iter);
}

void *tr_list_iter_next(TR_LIST_ITER *iter)
{
  if (!iter)
    return NULL;

  if (iter->index < (*(iter->list))->len)
    return g_ptr_array_index(*(iter->list), iter->index++);
  return NULL;
}
