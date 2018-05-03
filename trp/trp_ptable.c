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

#include <time.h>
#include <talloc.h>

#include <tr_name_internal.h>
#include <trp_internal.h>
#include <tr_gss_names.h>
#include <trp_ptable.h>
#include <tr_debug.h>
#include <trp_peer.h>


TRP_PTABLE *trp_ptable_new(TALLOC_CTX *memctx)
{
  TRP_PTABLE *ptbl=talloc(memctx, TRP_PTABLE);
  if (ptbl!=NULL) {
    ptbl->head=NULL;
  }
  return ptbl;
}

void trp_ptable_free(TRP_PTABLE *ptbl)
{
  talloc_free(ptbl);
}

TRP_RC trp_ptable_add(TRP_PTABLE *ptbl, TRP_PEER *newpeer)
{
  if (ptbl->head==NULL)
    ptbl->head=newpeer;
  else
    trp_peer_tail(ptbl->head)->next=newpeer;

  talloc_steal(ptbl, newpeer);
  return TRP_SUCCESS;
}

/* peer pointer is invalid after successful removal. Does nothing and returns
 * TRP_ERROR if peer is not in the list. */
TRP_RC trp_ptable_remove(TRP_PTABLE *ptbl, TRP_PEER *peer)
{
  TRP_PEER *cur=NULL;
  TRP_PEER *last=NULL;
  if (ptbl->head!=NULL) {
    if (ptbl->head==peer) {
      /* special case for removing head of list */
      cur=ptbl->head;
      ptbl->head=ptbl->head->next; /* advance the head */
      trp_peer_free(cur);
    }
    for (cur=ptbl->head->next; cur!=NULL; last=cur,cur=cur->next) {
      if (cur==peer) {
        if (last!=NULL)
          last->next=cur->next;
        trp_peer_free(cur);
        return TRP_SUCCESS;
      }
    }
  }
  return TRP_ERROR;
}

TRP_PEER *trp_ptable_find_gss_name(TRP_PTABLE *ptbl, TR_NAME *gssname)
{
  TRP_PEER *cur=ptbl->head;
  while ((cur!=NULL) && (!tr_gss_names_matches(trp_peer_get_gss_names(cur), gssname)))
    cur=cur->next;
  return cur;
}

TRP_PEER *trp_ptable_find_servicename(TRP_PTABLE *ptbl, TR_NAME *servicename)
{
  TRP_PEER *cur=ptbl->head;
  while ((cur!=NULL) && (0 != tr_name_cmp(trp_peer_get_servicename(cur), servicename)))
    cur=cur->next;
  return cur;
}

TRP_PTABLE_ITER *trp_ptable_iter_new(TALLOC_CTX *mem_ctx)
{
  TRP_PTABLE_ITER *iter=talloc(mem_ctx, TRP_PTABLE_ITER);
  *iter=NULL;
  return iter;
}

TRP_PEER *trp_ptable_iter_first(TRP_PTABLE_ITER *iter, TRP_PTABLE *ptbl)
{
  if (ptbl==NULL)
    *iter=NULL;
  else
    *iter=ptbl->head;
  return *iter;
}

TRP_PEER *trp_ptable_iter_next(TRP_PTABLE_ITER *iter)
{
  if (*iter!=NULL)
    *iter=(*iter)->next;
  return *iter;
}

void trp_ptable_iter_free(TRP_PTABLE_ITER *iter)
{
  talloc_free(iter);
}

