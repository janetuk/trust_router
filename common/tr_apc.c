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
