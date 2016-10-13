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

#include <talloc.h>

#include <trust_router/tr_name.h>
#include <tr_apc.h>
#include <tr_debug.h>

static int tr_apc_destructor(void *obj)
{
  TR_APC *apc=talloc_get_type_abort(obj, TR_APC);
  if (apc->id!=NULL)
    tr_free_name(apc->id);
  return 0;
}

TR_APC *tr_apc_new(TALLOC_CTX *mem_ctx)
{
  TR_APC *apc=talloc(mem_ctx, TR_APC);
  if (apc!=NULL) {
    apc->id=NULL;
    apc->next=NULL;
    talloc_set_destructor((void *)apc, tr_apc_destructor);
  }
  return apc;
}

void tr_apc_free(TR_APC *apc)
{
  talloc_free(apc);
}

static TR_APC *tr_apc_tail(TR_APC *apc)
{
  if (apc==NULL)
    return NULL;

  while (apc->next!=NULL)
    apc=apc->next;
  return apc;
}

/* do not call this directly, use the tr_apc_add() macro */
TR_APC *tr_apc_add_func(TR_APC *head, TR_APC *new)
{
  if (head==NULL)
    head=new;
  else {
    tr_apc_tail(head)->next=new;
    while (new!=NULL) {
      talloc_steal(head, new);
      new=new->next;
    }
  }
  return head;
}

/* does not copy next pointer */
TR_APC *tr_apc_dup(TALLOC_CTX *mem_ctx, TR_APC *apc)
{
  TR_APC *new=tr_apc_new(mem_ctx);
  tr_apc_set_id(new, tr_apc_dup_id(apc));
  return new;
}

void tr_apc_set_id(TR_APC *apc, TR_NAME *id)
{
  if (apc->id)
    tr_free_name(apc->id);
  apc->id=id;
}

TR_NAME *tr_apc_get_id(TR_APC *apc)
{
  return apc->id;
}

TR_NAME *tr_apc_dup_id(TR_APC *apc)
{
  return tr_dup_name(apc->id);;
}


char *tr_apc_to_str(TALLOC_CTX *mem_ctx, TR_APC *apc)
{
  return talloc_strndup(mem_ctx, apc->id->buf, apc->id->len);
}

TR_APC_ITER *tr_apc_iter_new(TALLOC_CTX *mem_ctx)
{
  return talloc(mem_ctx, TR_APC_ITER);
}

TR_APC *tr_apc_iter_first(TR_APC_ITER *iter, TR_APC *apc)
{
  *iter=apc;
  return *iter;
}

TR_APC *tr_apc_iter_next(TR_APC_ITER *iter)
{
  (*iter)=(*iter)->next;
  return *iter;
}

void tr_apc_iter_free(TR_APC_ITER *iter)
{
  talloc_free(iter);
}

/* 1 on match, 0 on no match, -1 on error */
int tr_apc_in_common(TR_APC *one, TR_APC *two)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_APC_ITER *i_one=tr_apc_iter_new(tmp_ctx);
  TR_APC_ITER *i_two=tr_apc_iter_new(tmp_ctx);
  TR_APC *cur_one=NULL;
  TR_APC *cur_two=NULL;

  if ((i_one==NULL) || (i_two==NULL)) {
    tr_err("tr_apc_in_common: unable to allocate iterators.");
    talloc_free(tmp_ctx);
    return -1;
  }
  for (cur_one=tr_apc_iter_first(i_one, one); cur_one!=NULL; cur_one=tr_apc_iter_next(i_one)) {
    for (cur_two=tr_apc_iter_first(i_two, two); cur_two!=NULL; cur_two=tr_apc_iter_next(i_two)) {
      if (cur_one==cur_two)
        return 1;
    }
  }
  return 0;
}
