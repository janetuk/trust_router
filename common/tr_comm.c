/*
 * Copyright (c) 2012-2018, JANET(UK)
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

#include <stdio.h>
#include <jansson.h>
#include <talloc.h>
#include <sys/time.h>

#include <tr_rp.h>
#include <tr_idp.h>
#include <tr_name_internal.h>
#include <tr_comm.h>
#include <tr_debug.h>


static int tr_comm_destructor(void *obj)
{
  TR_COMM *comm=talloc_get_type_abort(obj, TR_COMM);
  if (comm->id!=NULL)
    tr_free_name(comm->id);
  if (comm->owner_realm!=NULL)
    tr_free_name(comm->owner_realm);
  if (comm->owner_contact!=NULL)
    tr_free_name(comm->owner_contact);
  return 0;
}

TR_COMM *tr_comm_new(TALLOC_CTX *mem_ctx)
{
  TR_COMM *comm=talloc(mem_ctx, TR_COMM);
  if (comm!=NULL) {
    comm->next=NULL;
    comm->id=NULL;
    comm->type=TR_COMM_UNKNOWN;
    comm->apcs=NULL;
    comm->owner_realm=NULL;
    comm->owner_contact=NULL;
    comm->expiration_interval=0;
    comm->refcount=0;
    talloc_set_destructor((void *)comm, tr_comm_destructor);
  }
  return comm;
}

void tr_comm_free(TR_COMM *comm)
{
  talloc_free(comm);
}

void tr_comm_set_id(TR_COMM *comm, TR_NAME *id)
{
  if (comm->id != NULL)
    tr_free_name(comm->id);
  comm->id=id;
}

void tr_comm_incref(TR_COMM *comm)
{
  comm->refcount++;
}

void tr_comm_decref(TR_COMM *comm)
{
  if (comm->refcount>0)
    comm->refcount--;
}

void tr_comm_set_apcs(TR_COMM *comm, TR_APC *apc)
{
  if (comm->apcs!=NULL)
    tr_apc_free(comm->apcs);
  comm->apcs=apc;
  talloc_steal(comm, apc);
}

TR_APC *tr_comm_get_apcs(TR_COMM *comm)
{
  return comm->apcs;
}

TR_NAME *tr_comm_get_id(TR_COMM *comm)
{
  return comm->id;
}

TR_NAME *tr_comm_dup_id(TR_COMM *comm)
{
  return tr_dup_name(comm->id);
}

void tr_comm_set_type(TR_COMM *comm, TR_COMM_TYPE type)
{
  comm->type=type;
}

TR_COMM_TYPE tr_comm_get_type(TR_COMM *comm)
{
  return comm->type;
}

void tr_comm_set_owner_realm(TR_COMM *comm, TR_NAME *realm)
{
  if (comm->owner_realm!=NULL)
    tr_free_name(comm->owner_realm);
  comm->owner_realm=realm;
}

TR_NAME *tr_comm_get_owner_realm(TR_COMM *comm)
{
  return comm->owner_realm;
}

TR_NAME *tr_comm_dup_owner_realm(TR_COMM *comm)
{
  return tr_dup_name(comm->owner_realm);
}

void tr_comm_set_owner_contact(TR_COMM *comm, TR_NAME *contact)
{
  if (comm->owner_contact != NULL)
    tr_free_name(comm->owner_contact);
  comm->owner_contact=contact;
}

TR_NAME *tr_comm_get_owner_contact(TR_COMM *comm)
{
  return comm->owner_contact;
}

TR_NAME *tr_comm_dup_owner_contact(TR_COMM *comm)
{
  return tr_dup_name(comm->owner_contact);
}

unsigned int tr_comm_get_refcount(TR_COMM *comm)
{
  return comm->refcount;
}

/* 0 if equivalent, nonzero if different, only considers
 * nhops last hops (nhops==0 means consider all, nhops==1
 * only considers last hop) */
static int tr_comm_memb_provenance_cmp(TR_COMM_MEMB *m1, TR_COMM_MEMB *m2, int nhops)
{
  size_t ii;

  if ((m1->provenance==NULL) || (m2->provenance==NULL))
    return m1->provenance!=m2->provenance; /* return 0 if both null, 1 if only one null */

  if (json_array_size(m1->provenance)!=json_array_size(m2->provenance))
    return 1;

  if (nhops==0)
    nhops=json_array_size(m1->provenance); /* same as size(m2->provenance) */

  for (ii=0; ii<json_array_size(m1->provenance); ii++) {
    if (0==strcmp(json_string_value(json_array_get(m1->provenance, ii)),
                  json_string_value(json_array_get(m2->provenance, ii)))) {
      return 0;
    }
  }
  return 1;
}

/* Accepts an update that either came from the same peer as the previous
 * origin, has a shorter provenance list, or can replace an expired
 * membership. Otherwise keeps the existing one.
 * On replacement, frees the old member and moves new member to ctab's
 * context. Caller should not free newmemb except by freeing its original
 * context. */
static void tr_comm_add_if_shorter(TR_COMM_TABLE *ctab, TR_COMM_MEMB *existing, TR_COMM_MEMB *newmemb)
{
  int accept=0;

  if (existing==NULL) {
    /* not in the table */
    tr_comm_table_add_memb(ctab, newmemb);
  } else {
    if (0==tr_comm_memb_provenance_cmp(existing, newmemb, 1))
      accept=1; /* always accept a replacement from the same peer */
    else if (tr_comm_memb_provenance_len(newmemb) < tr_comm_memb_provenance_len(existing))
      accept=1; /* accept a shorter provenance */
    else if (existing->times_expired>0)
      accept=1;
    else
      accept=0;

    if (accept) {
      tr_comm_table_remove_memb(ctab, existing);
      tr_comm_memb_free(existing);
      tr_comm_table_add_memb(ctab, newmemb);
    }
  }
}

/* does not take responsibility for freeing IDP realm */
void tr_comm_add_idp_realm(TR_COMM_TABLE *ctab,
                           TR_COMM *comm,
                           TR_IDP_REALM *realm,
                           unsigned int interval,
                           json_t *provenance,
                           struct timespec *expiry)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM_MEMB *newmemb=tr_comm_memb_new(tmp_ctx);
  TR_COMM_MEMB *existing=NULL;

  if (newmemb==NULL) {
    tr_err("tr_comm_add_idp_realm: unable to allocate new membership record.");
    talloc_free(tmp_ctx);
    return;
  }

  tr_comm_memb_set_idp_realm(newmemb, realm);
  tr_comm_memb_set_comm(newmemb, comm);
  tr_comm_memb_set_interval(newmemb, interval);
  tr_comm_memb_set_provenance(newmemb, provenance);
  tr_comm_memb_set_expiry(newmemb, expiry);

  existing=tr_comm_table_find_idp_memb_origin(ctab,
                                              tr_idp_realm_get_id(realm),
                                              tr_comm_get_id(comm),
                                              tr_comm_memb_get_origin(newmemb));
  tr_comm_add_if_shorter(ctab, existing, newmemb); /* takes newmemb out of tmp_ctx if needed */

  talloc_free(tmp_ctx);
}

/* does not take responsibility for freeing RP realm */
void tr_comm_add_rp_realm(TR_COMM_TABLE *ctab,
                          TR_COMM *comm,
                          TR_RP_REALM *realm,
                          unsigned int interval,
                          json_t *provenance,
                          struct timespec *expiry)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM_MEMB *newmemb=tr_comm_memb_new(tmp_ctx);
  TR_COMM_MEMB *existing=NULL;

  if (newmemb==NULL) {
    tr_err("tr_comm_add_idp_realm: unable to allocate new membership record.");
    talloc_free(tmp_ctx);
    return;
  }

  tr_comm_memb_set_rp_realm(newmemb, realm);
  tr_comm_memb_set_comm(newmemb, comm);
  tr_comm_memb_set_interval(newmemb, interval);
  tr_comm_memb_set_provenance(newmemb, provenance);
  tr_comm_memb_set_expiry(newmemb, expiry);

  existing=tr_comm_table_find_rp_memb_origin(ctab,
                                             tr_rp_realm_get_id(realm),
                                             tr_comm_get_id(comm),
                                             tr_comm_memb_get_origin(newmemb));
  tr_comm_add_if_shorter(ctab, existing, newmemb); /* takes newmemb out of tmp_ctx if needed */
  talloc_free(tmp_ctx);
}

static TR_COMM *tr_comm_tail(TR_COMM *comm)
{
  if (comm==NULL)
    return comm;

  while (comm->next!=NULL)
    comm=comm->next;
  return comm;
}

/* All list members are in the talloc context of the head.
 * This will require careful thought if entries are ever removed
 * Call like comms=tr_comm_add_func(comms, new_comm);
 * or just use the tr_comm_add(comms, new) macro. */
#define tr_comm_add(comms, new) ((comms)=tr_comm_add_func((comms), (new)))
static TR_COMM *tr_comm_add_func(TR_COMM *comms, TR_COMM *new)
{
  if (comms==NULL)
    comms=new;
  else {
    tr_comm_tail(comms)->next=new;
    while(new!=NULL) {
      talloc_steal(comms, new);
      new=new->next;
    }
  }
  return comms;
}

/* Guarantees comm is not in the list, not an error if it was't there.
 * Does not free the removed element, nor change its talloc context. */
#define tr_comm_remove(comms, c) ((comms)=tr_comm_remove_func((comms), (c)))
static TR_COMM *tr_comm_remove_func(TR_COMM *comms, TR_COMM *remove)
{
  TALLOC_CTX *list_ctx=talloc_parent(comms); /* in case we need to remove the head */
  TR_COMM *this=NULL;

  if (comms==NULL)
    return NULL;

  if (comms==remove) {
    /* if we're removing the head, put the next element (if present) into the context
     * the list head was in. */
    comms=comms->next;
    if (comms!=NULL) {
      talloc_steal(list_ctx, comms);
      /* now put all the other elements in the context of the list head */
      for (this=comms->next; this!=NULL; this=this->next)
        talloc_steal(comms, this);
    }
  } else {
    /* not removing the head; no need to play with contexts */
    for (this=comms; this->next!=NULL; this=this->next) {
      if (this->next==remove) {
        this->next=remove->next;
        break;
      }
    }
  }
  return comms;
}

/* remove any with zero refcount 
 * Call via macro. */
#define tr_comm_sweep(head) ((head)=tr_comm_sweep_func((head)))
static TR_COMM *tr_comm_sweep_func(TR_COMM *head)
{
  TR_COMM *comm=NULL;
  TR_COMM *old_next=NULL;

  if (head==NULL)
    return NULL;

  while ((head!=NULL) && (head->refcount==0)) {
    comm=head; /* keep a pointer so we can remove it */
    tr_comm_remove(head, comm); /* use this to get talloc contexts right */
    tr_comm_free(comm);
  }

  if (head==NULL)
    return NULL;

  /* will not remove the head here, that has already been done */
  for (comm=head; (comm!=NULL) && (comm->next!=NULL); comm=comm->next) {
    if (comm->next->refcount==0) {
      old_next=comm->next;
      tr_comm_remove(head, comm->next); /* changes comm->next, may make it null */
      tr_comm_free(old_next);
    }
  }

  return head;
}

TR_IDP_REALM *tr_comm_find_idp(TR_COMM_TABLE *ctab, TR_COMM *comm, TR_NAME *idp_realm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM_ITER *iter=NULL;
  TR_IDP_REALM *this_idp=NULL;

  if ((NULL==ctab) || (NULL==comm) || (NULL==idp_realm)) {
    talloc_free(tmp_ctx);
    return NULL;
  }

  iter=tr_comm_iter_new(tmp_ctx);
  for (this_idp=tr_idp_realm_iter_first(iter, ctab, tr_comm_get_id(comm));
       this_idp!=NULL;
       this_idp=tr_idp_realm_iter_next(iter)) {
    if (0==tr_name_cmp(idp_realm, tr_idp_realm_get_id(this_idp))) {
      tr_debug("tr_comm_find_idp: Found IdP %s in community %s.", idp_realm->buf, tr_comm_get_id(comm)->buf);
      talloc_free(tmp_ctx);
      return this_idp;
    }
  }
  tr_debug("tr_comm_find_idp: Unable to find IdP %s in community %s.", idp_realm->buf, tr_comm_get_id(comm)->buf);
  talloc_free(tmp_ctx);
  return NULL;
}

TR_RP_REALM *tr_comm_find_rp (TR_COMM_TABLE *ctab, TR_COMM *comm, TR_NAME *rp_realm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM_ITER *iter=NULL;
  TR_RP_REALM *this_rp=NULL;

  if ((NULL==ctab) || (NULL==comm) || (NULL==rp_realm)) {
    talloc_free(tmp_ctx);
    return NULL;
  }

  iter=tr_comm_iter_new(tmp_ctx);
  for (this_rp=tr_rp_realm_iter_first(iter, ctab, tr_comm_get_id(comm));
       this_rp!=NULL;
       this_rp=tr_rp_realm_iter_next(iter)) {
    if (0==tr_name_cmp(rp_realm, tr_rp_realm_get_id(this_rp))) {
      tr_debug("tr_comm_find_rp: Found RP %s in community %s.", rp_realm->buf, tr_comm_get_id(comm)->buf);
      talloc_free(tmp_ctx);
      return this_rp;
    }
  }
  tr_debug("tr_comm_find_rp: Unable to find RP %s in community %s.", rp_realm->buf, tr_comm_get_id(comm)->buf);
  talloc_free(tmp_ctx);
  return NULL;
}

static TR_COMM *tr_comm_lookup(TR_COMM *comms, TR_NAME *comm_name) 
{
  TR_COMM *cfg_comm = NULL;

  for (cfg_comm = comms; NULL != cfg_comm; cfg_comm = cfg_comm->next) {
    if (0==tr_name_cmp(cfg_comm->id, comm_name))
      return cfg_comm;
  }
  return NULL;
}

TR_COMM_ITER *tr_comm_iter_new(TALLOC_CTX *mem_ctx)
{
  TR_COMM_ITER *iter=talloc(mem_ctx, TR_COMM_ITER);
  if (iter!=NULL) {
    iter->cur_comm=NULL;
    iter->cur_memb=NULL;
    iter->cur_orig_head=NULL;
    iter->match=NULL;
    iter->realm=NULL;
  }
  return iter;
}

void tr_comm_iter_free(TR_COMM_ITER *iter)
{
  talloc_free(iter);
}


TR_COMM *tr_comm_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *realm)
{
  iter->match=realm;

  /* find memberships for this realm */
  for (iter->cur_memb=ctab->memberships;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if (0==tr_name_cmp(iter->match, tr_comm_memb_get_realm_id(iter->cur_memb)))
      return tr_comm_memb_get_comm(iter->cur_memb);
  }
  return NULL;
}

TR_COMM *tr_comm_iter_next(TR_COMM_ITER *iter)
{
  for (iter->cur_memb=iter->cur_memb->next;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if (0==tr_name_cmp(iter->match, tr_comm_memb_get_realm_id(iter->cur_memb)))
      return tr_comm_memb_get_comm(iter->cur_memb);
  }
  return NULL;
}

/* iterate only over RPs */
TR_COMM *tr_comm_iter_first_rp(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *realm)
{
  iter->match=realm;

  /* find memberships for this realm */
  for (iter->cur_memb=ctab->memberships;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if ((tr_comm_memb_get_rp_realm(iter->cur_memb)!=NULL) &&
        (0==tr_name_cmp(iter->match, tr_comm_memb_get_realm_id(iter->cur_memb))))
      return tr_comm_memb_get_comm(iter->cur_memb);
  }
  return NULL;
}

TR_COMM *tr_comm_iter_next_rp(TR_COMM_ITER *iter)
{
  for (iter->cur_memb=iter->cur_memb->next;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if ((tr_comm_memb_get_rp_realm(iter->cur_memb)!=NULL) &&
        (0==tr_name_cmp(iter->match, tr_comm_memb_get_realm_id(iter->cur_memb))))
      return tr_comm_memb_get_comm(iter->cur_memb);
  }
  return NULL;
}

/* iterate only over IDPs */
TR_COMM *tr_comm_iter_first_idp(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *realm)
{
  iter->match=realm;

  /* find memberships for this realm */
  for (iter->cur_memb=ctab->memberships;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if ((tr_comm_memb_get_idp_realm(iter->cur_memb)!=NULL) &&
        (0==tr_name_cmp(iter->match, tr_comm_memb_get_realm_id(iter->cur_memb))))
      return tr_comm_memb_get_comm(iter->cur_memb);
  }
  return NULL;
}

TR_COMM *tr_comm_iter_next_idp(TR_COMM_ITER *iter)
{
  for (iter->cur_memb=iter->cur_memb->next;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if ((tr_comm_memb_get_idp_realm(iter->cur_memb)!=NULL) &&
        (0==tr_name_cmp(iter->match, tr_comm_memb_get_realm_id(iter->cur_memb))))
      return tr_comm_memb_get_comm(iter->cur_memb);
  }
  return NULL;
}

static TR_REALM *tr_realm_new(TALLOC_CTX *mem_ctx)
{
  TR_REALM *realm=talloc(mem_ctx, TR_REALM);
  if (realm!=NULL) {
    realm->role=TR_ROLE_UNKNOWN;
    realm->rp=NULL;
    realm->idp=NULL;
  }
  return realm;
}

static void tr_realm_free(TR_REALM *realm)
{
  talloc_free(realm);
}

static void tr_realm_set_rp(TR_REALM *realm, TR_RP_REALM *rp)
{
  if (realm->idp!=NULL)
    realm->idp=NULL;
  realm->role=TR_ROLE_RP;
  realm->rp=rp;
}

static void tr_realm_set_idp(TR_REALM *realm, TR_IDP_REALM *idp)
{
  if (realm->rp!=NULL)
    realm->rp=NULL;
  realm->role=TR_ROLE_IDP;
  realm->idp=idp;
}

TR_NAME *tr_realm_get_id(TR_REALM *realm)
{
  switch (realm->role) {
  case TR_ROLE_RP:
    return tr_rp_realm_get_id(realm->rp);
  case TR_ROLE_IDP:
    return tr_idp_realm_get_id(realm->idp);
  default:
    break;
  }
  return NULL;
}

TR_NAME *tr_realm_dup_id(TR_REALM *realm)
{
  return tr_dup_name(tr_realm_get_id(realm));
}

/* Iterate over either sort of realm. Do not free the TR_REALM returned. It becomes
 * undefined/invalid after the next operation affecting the iterator. */
TR_REALM *tr_realm_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *comm)
{
  iter->match=comm;
  if (iter->realm==NULL)
    iter->realm=tr_realm_new(iter);
  if (iter->realm==NULL)
    return NULL;

  /* find memberships for this comm */
  for (iter->cur_memb=ctab->memberships;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if (0==tr_name_cmp(iter->match,
                       tr_comm_get_id(tr_comm_memb_get_comm(iter->cur_memb)))) {
      /* found a match, determine whether it's an rp realm or an idp realm */
      if (tr_comm_memb_get_rp_realm(iter->cur_memb)!=NULL)
        tr_realm_set_rp(iter->realm, tr_comm_memb_get_rp_realm(iter->cur_memb));
      else if (tr_comm_memb_get_idp_realm(iter->cur_memb)!=NULL)
        tr_realm_set_idp(iter->realm, tr_comm_memb_get_idp_realm(iter->cur_memb));
      else {
        if (iter->realm!=NULL)
          tr_realm_free(iter->realm);
        iter->realm=NULL;
      }
      return iter->realm;
    }
  }
  if (iter->realm!=NULL)
    tr_realm_free(iter->realm);
  iter->realm=NULL;
  return NULL;
}

TR_REALM *tr_realm_iter_next(TR_COMM_ITER *iter)
{
  if (iter->realm==NULL)
    return NULL;

  /* find memberships for this comm */
  for (iter->cur_memb=iter->cur_memb->next;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if (0==tr_name_cmp(iter->match,
                       tr_comm_get_id(tr_comm_memb_get_comm(iter->cur_memb)))) {
      /* found a match, determine whether it's an rp realm or an idp realm */
      if (tr_comm_memb_get_rp_realm(iter->cur_memb)!=NULL)
        tr_realm_set_rp(iter->realm, tr_comm_memb_get_rp_realm(iter->cur_memb));
      else if (tr_comm_memb_get_idp_realm(iter->cur_memb)!=NULL)
        tr_realm_set_idp(iter->realm, tr_comm_memb_get_idp_realm(iter->cur_memb));
      else {
        if (iter->realm!=NULL)
          tr_realm_free(iter->realm);
        iter->realm=NULL;
      }
      return iter->realm;
    }
  }
  if (iter->realm!=NULL)
    tr_realm_free(iter->realm);
  iter->realm=NULL;
  return NULL;
}

TR_RP_REALM *tr_rp_realm_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *comm)
{
  iter->match=comm;

  /* find memberships for this comm */
  for (iter->cur_memb=ctab->memberships;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if ((tr_comm_memb_get_rp_realm(iter->cur_memb)!=NULL) &&
        (0==tr_name_cmp(iter->match, tr_comm_get_id(tr_comm_memb_get_comm(iter->cur_memb)))))
      return tr_comm_memb_get_rp_realm(iter->cur_memb);
  }
  return NULL;
}

TR_RP_REALM *tr_rp_realm_iter_next(TR_COMM_ITER *iter)
{
  for (iter->cur_memb=iter->cur_memb->next;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if ((tr_comm_memb_get_rp_realm(iter->cur_memb)!=NULL) &&
        (0==tr_name_cmp(iter->match, tr_comm_get_id(tr_comm_memb_get_comm(iter->cur_memb)))))
      return tr_comm_memb_get_rp_realm(iter->cur_memb);
  }
  return NULL;
}

TR_IDP_REALM *tr_idp_realm_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab, TR_NAME *comm)
{
  iter->match=comm;

  /* find memberships for this comm */
  for (iter->cur_memb=ctab->memberships;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if ((tr_comm_memb_get_idp_realm(iter->cur_memb)!=NULL) &&
        (0==tr_name_cmp(iter->match, tr_comm_get_id(tr_comm_memb_get_comm(iter->cur_memb)))))
      return tr_comm_memb_get_idp_realm(iter->cur_memb);
  }
  return NULL;
}

TR_IDP_REALM *tr_idp_realm_iter_next(TR_COMM_ITER *iter)
{
  for (iter->cur_memb=iter->cur_memb->next;
       iter->cur_memb!=NULL;
       iter->cur_memb=iter->cur_memb->next) {
    if ((tr_comm_memb_get_idp_realm(iter->cur_memb)!=NULL) &&
        (0==tr_name_cmp(iter->match, tr_comm_get_id(tr_comm_memb_get_comm(iter->cur_memb)))))
      return tr_comm_memb_get_idp_realm(iter->cur_memb);
  }
  return NULL;
}

/* iterators for all communities in a table */
TR_COMM *tr_comm_table_iter_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab)
{
  iter->cur_comm=ctab->comms;
  return iter->cur_comm;
}

TR_COMM *tr_comm_table_iter_next(TR_COMM_ITER *iter)
{
  return iter->cur_comm=iter->cur_comm->next;
}

const char *tr_comm_type_to_str(TR_COMM_TYPE type)
{
  const char *s=NULL;
  switch(type) {
  case TR_COMM_UNKNOWN:
    s="unknown";
    break;
  case TR_COMM_APC:
    s="apc";
    break;
  case TR_COMM_COI:
    s="coi";
    break;
  default:
    s="invalid";
  }
  return s;
}

/* iterate along the origin list for this member */
TR_COMM_MEMB *tr_comm_memb_iter_first(TR_COMM_ITER *iter, TR_COMM_MEMB *memb)
{
  iter->cur_memb=memb;
  return iter->cur_memb;
}

TR_COMM_MEMB *tr_comm_memb_iter_next(TR_COMM_ITER *iter)
{
  if (iter->cur_memb!=NULL)
    iter->cur_memb=iter->cur_memb->origin_next;
  return iter->cur_memb;
}


/* iterate over all memberships in the table */
TR_COMM_MEMB *tr_comm_memb_iter_all_first(TR_COMM_ITER *iter, TR_COMM_TABLE *ctab)
{
  iter->cur_memb=ctab->memberships;
  iter->cur_orig_head=ctab->memberships;
  return iter->cur_memb;
}

TR_COMM_MEMB *tr_comm_memb_iter_all_next(TR_COMM_ITER *iter)
{
  if (iter->cur_memb->next==NULL) {
    if (iter->cur_orig_head->next==NULL) {
      /* we're done */
      return NULL;
    } else {
      iter->cur_memb=iter->cur_orig_head->next;
      iter->cur_orig_head=iter->cur_orig_head->next;
    }
  } else {
    iter->cur_memb=iter->cur_memb->origin_next;
  }
  return iter->cur_memb;
}


TR_COMM_TYPE tr_comm_type_from_str(const char *s)
{
  if (strcmp(s, "apc")==0)
    return TR_COMM_APC;
  if (strcmp(s,"coi")==0)
    return TR_COMM_COI;
  return TR_COMM_UNKNOWN;
}


static int tr_comm_memb_destructor(void *obj)
{
  TR_COMM_MEMB *memb=talloc_get_type_abort(obj, TR_COMM_MEMB);
  if (memb->origin!=NULL)
    tr_free_name(memb->origin);

  if (memb->rp!=NULL)
    tr_rp_realm_decref(memb->rp);
  if (memb->idp!=NULL)
    tr_idp_realm_decref(memb->idp);
  if (memb->comm!=NULL)
    tr_comm_decref(memb->comm);
  if (memb->provenance!=NULL)
    json_decref(memb->provenance);
  return 0;
}

TR_COMM_MEMB *tr_comm_memb_new(TALLOC_CTX *mem_ctx)
{
  TR_COMM_MEMB *memb=talloc(mem_ctx, TR_COMM_MEMB);
  if (memb!=NULL) {
    memb->next=NULL;
    memb->origin_next=NULL;
    memb->idp=NULL;
    memb->rp=NULL;
    memb->comm=NULL;
    memb->origin=NULL;
    memb->provenance=NULL;
    memb->interval=0;
    memb->triggered=0;
    memb->times_expired=0;
    memb->expiry=talloc(memb, struct timespec);
    if (memb->expiry==NULL) {
      talloc_free(memb);
      return NULL;
    }
    *(memb->expiry)=(struct timespec){0,0};
    talloc_set_destructor((void *)memb, tr_comm_memb_destructor);
  }
  return memb;
}

void tr_comm_memb_free(TR_COMM_MEMB *memb)
{
  talloc_free(memb);
}

/* Returns 0 if they are the same, nonzero if they differ.
 * Ignores expiry, triggered, and times_expired, next pointers */
int tr_comm_memb_cmp(TR_COMM_MEMB *m1, TR_COMM_MEMB *m2)
{
  if ((m1->idp==m2->idp) &&
      (m1->rp==m2->rp) &&
      (m1->comm==m2->comm) &&
      (tr_comm_memb_provenance_cmp(m1, m2, 0)==0) &&
      (m1->interval==m2->interval))
    return 0;
  return 1;
}

TR_REALM_ROLE tr_comm_memb_get_role(TR_COMM_MEMB *memb)
{
  if (memb->rp!=NULL)
    return TR_ROLE_RP;
  if (memb->idp!=NULL)
    return TR_ROLE_IDP;
  return TR_ROLE_UNKNOWN;
}

void tr_comm_memb_set_rp_realm(TR_COMM_MEMB *memb, TR_RP_REALM *realm)
{
  if (memb->idp!=NULL) {
    tr_idp_realm_decref(memb->idp);
    memb->idp=NULL;
  }
  if (memb->rp!=NULL)
    tr_rp_realm_decref(memb->rp);


  memb->rp=realm;
  tr_rp_realm_incref(realm);
}

TR_RP_REALM *tr_comm_memb_get_rp_realm(TR_COMM_MEMB *memb)
{
  return memb->rp;
}

void tr_comm_memb_set_idp_realm(TR_COMM_MEMB *memb, TR_IDP_REALM *realm)
{
  if (memb->rp!=NULL) {
    tr_rp_realm_decref(memb->rp);
    memb->rp=NULL;
  }
  if (memb->idp!=NULL)
    tr_idp_realm_decref(memb->idp);

  memb->idp=realm;
  tr_idp_realm_incref(realm);
}

TR_IDP_REALM *tr_comm_memb_get_idp_realm(TR_COMM_MEMB *memb)
{
  return memb->idp;
}

void tr_comm_memb_set_comm(TR_COMM_MEMB *memb, TR_COMM *comm)
{
  if (memb->comm!=NULL)
    tr_comm_decref(memb->comm);
  memb->comm=comm;
  tr_comm_incref(comm);
}

TR_COMM *tr_comm_memb_get_comm(TR_COMM_MEMB *memb)
{
  return memb->comm;
}

static void tr_comm_memb_set_origin(TR_COMM_MEMB *memb, TR_NAME *origin)
{
  if (memb->origin!=NULL)
    tr_free_name(memb->origin);
  memb->origin=origin;
}

TR_NAME *tr_comm_memb_get_origin(TR_COMM_MEMB *memb)
{
  return memb->origin;
}

TR_NAME *tr_comm_memb_dup_origin(TR_COMM_MEMB *memb)
{
  if (memb->origin!=NULL)
    return tr_dup_name(memb->origin);
  return NULL;
}

json_t *tr_comm_memb_get_provenance(TR_COMM_MEMB *memb)
{
  if (memb!=NULL)
    return memb->provenance;
  return NULL;
}

void tr_comm_memb_set_provenance(TR_COMM_MEMB *memb, json_t *prov)
{
  const char *s=NULL;

  if (memb->provenance)
    json_decref(memb->provenance);

  memb->provenance=prov;
  if (prov!=NULL) {
    json_incref(prov);

    /* next line sets origin to NULL if provenance is empty because jansson
     * routines return NULL on error */
    s=json_string_value(json_array_get(prov, 0));
    if (s==NULL)
      tr_comm_memb_set_origin(memb, NULL);
    else
      memb->origin=tr_new_name(s);
  } else {
    tr_comm_memb_set_origin(memb, NULL);
  }
}

void tr_comm_memb_add_to_provenance(TR_COMM_MEMB *memb, TR_NAME *hop)
{
  if (memb->provenance==NULL) {
    memb->provenance=json_array();
    if (memb->provenance==NULL) {
      tr_err("tr_comm_memb_add_to_provenance: unable to allocate provenance list.");
      return;
    }
    /* this is the first entry in the provenance, so it is the origin */
    tr_comm_memb_set_origin(memb,tr_dup_name(hop));
    if (memb->origin==NULL) {
      tr_err("tr_comm_memb_add_to_provenance: unable to allocate origin.");
      json_decref(memb->provenance);
      memb->provenance=NULL;
      return;
    }
  }
  if (0!=json_array_append_new(memb->provenance, tr_name_to_json_string(hop)))
    tr_err("tr_comm_memb_add_to_provenance: unable to extend provenance list.");
}

size_t tr_comm_memb_provenance_len(TR_COMM_MEMB *memb)
{
  if (memb->provenance==NULL)
    return 0;
  return json_array_size(memb->provenance);
}

void tr_comm_memb_set_interval(TR_COMM_MEMB *memb, unsigned int interval)
{
  memb->interval=interval;
}

unsigned int tr_comm_memb_get_interval(TR_COMM_MEMB *memb)
{
  return memb->interval;
}

void tr_comm_memb_set_expiry(TR_COMM_MEMB *memb, struct timespec *time)
{
  if (time==NULL)
    *(memb->expiry)=(struct timespec){0,0};
  else {
    memb->expiry->tv_sec=time->tv_sec;
    memb->expiry->tv_nsec=time->tv_nsec;
  }
}

struct timespec *tr_comm_memb_get_expiry(TR_COMM_MEMB *memb)
{
  return memb->expiry;
}

int tr_comm_memb_is_expired(TR_COMM_MEMB *memb, struct timespec *curtime)
{
  tr_debug("tr_comm_memb_is_expired: (cur->tv_sec>memb->expiry->tv_sec)=(%u > %u)=%s",
           curtime->tv_sec,
           memb->expiry->tv_sec,
           (curtime->tv_sec > memb->expiry->tv_sec)?"true":"false");

  return ((curtime->tv_sec > memb->expiry->tv_sec)
         || ((curtime->tv_sec == memb->expiry->tv_sec)
            &&(curtime->tv_nsec >= memb->expiry->tv_nsec)));
}

void tr_comm_memb_set_triggered(TR_COMM_MEMB *memb, int trig)
{
  memb->triggered=trig;
}

int tr_comm_memb_is_triggered(TR_COMM_MEMB *memb)
{
  return memb->triggered;
}

void tr_comm_memb_reset_times_expired(TR_COMM_MEMB *memb)
{
  memb->times_expired=0;
}

/* bumps the expiration count */
void tr_comm_memb_expire(TR_COMM_MEMB *memb)
{
  /* avoid overflow */
  if (memb->times_expired+1>memb->times_expired)
    memb->times_expired++;
}

unsigned int tr_comm_memb_get_times_expired(TR_COMM_MEMB *memb)
{
  return memb->times_expired;
}

TR_COMM_TABLE *tr_comm_table_new(TALLOC_CTX *mem_ctx)
{
  TR_COMM_TABLE *ctab=talloc(mem_ctx, TR_COMM_TABLE);
  if (ctab!=NULL) {
    ctab->comms=NULL;
    ctab->memberships=NULL;
    ctab->idp_realms=NULL;
    ctab->rp_realms=NULL;
  }
  return ctab;
}

void tr_comm_table_free(TR_COMM_TABLE *ctab)
{
  talloc_free(ctab);
}

static TR_REALM_ROLE tr_comm_memb_role(TR_COMM_MEMB *memb)
{
  if (memb->rp!=NULL)
    return TR_ROLE_RP;
  if (memb->idp!=NULL)
    return TR_ROLE_IDP;

  return TR_ROLE_UNKNOWN;
}

void tr_comm_table_add_memb(TR_COMM_TABLE *ctab, TR_COMM_MEMB *new)
{
  TR_COMM_MEMB *cur=NULL;

  /* TODO: further validate the member (must have valid comm and realm) */
  if ((new->next!=NULL) || (new->origin_next!=NULL)) {
    tr_debug("tr_comm_table_add_memb: attempting to add member already in a list.");
  }

  /* handle the empty list case */
  if (ctab->memberships==NULL) {
    ctab->memberships=new;
    talloc_steal(ctab, new);
    return;
  }

  /* The list was not empty. See if we already have a membership for this realm/comm/role */
  switch (tr_comm_memb_role(new)) {
  case TR_ROLE_RP:
    cur=tr_comm_table_find_rp_memb(ctab,
                                   tr_rp_realm_get_id(tr_comm_memb_get_rp_realm(new)),
                                   tr_comm_get_id(tr_comm_memb_get_comm(new)));
    break;
  case TR_ROLE_IDP:
    cur=tr_comm_table_find_idp_memb(ctab,
                                    tr_idp_realm_get_id(tr_comm_memb_get_idp_realm(new)),
                                    tr_comm_get_id(tr_comm_memb_get_comm(new)));
    break;
  case TR_ROLE_UNKNOWN:
  default:
    tr_err("tr_comm_table_add_memb: realm with unknown role added.");
    cur=NULL;
  }

  if (cur==NULL) {
    /* no entry for this realm/comm/role, tack it on the end */
    for (cur=ctab->memberships; cur->next!=NULL; cur=cur->next) { }
    cur->next=new;
  } else {
    /* Found an entry. Add to the end of its same-origin list. */
    while (cur->origin_next!=NULL) {
      cur=cur->origin_next;
    }
    cur->origin_next=new;
  }

  talloc_steal(ctab, new);
}

/* Remove memb from ctab. Do not free anything. Do nothing if memb not in ctab. */
void tr_comm_table_remove_memb(TR_COMM_TABLE *ctab, TR_COMM_MEMB *memb)
{
  TR_COMM_MEMB *cur=NULL; /* for walking the main list */
  TR_COMM_MEMB *orig_cur=NULL; /* for walking the origin list */

  if ((memb==NULL) || (ctab->memberships==NULL))
    return;

  /* see if it's the first member */
  if (ctab->memberships==memb) {
    if (memb->origin_next!=NULL) {
      memb->origin_next->next=memb->next;
      ctab->memberships=memb->origin_next;
    } else
      ctab->memberships=memb->next;

    return;
  }

  /* see if it's in first member's origin list */
  for (orig_cur=ctab->memberships;
       orig_cur->origin_next!=NULL;
       orig_cur=orig_cur->origin_next) {
    if (orig_cur->origin_next==memb) {
      orig_cur->origin_next=memb->origin_next;
      return;
    }
  }

  /* now we have to walk the rest of the tree */
  for (cur=ctab->memberships; cur->next!=NULL; cur=cur->next) {
    if (cur->next==memb) {
      /* it matched an entry on the main list */
      if (memb->origin_next==NULL)
        cur->next=memb->next; /* no origin list, just drop memb */
      else {
        /* replace the entry in the main list with the next element on the origin list */
        memb->origin_next->next=memb->next;
        cur->next=memb->origin_next;
      }
      return;
    } else {
      /* it was not on the main list, walk the origin list */
      for (orig_cur=cur; orig_cur->origin_next!=NULL; orig_cur=orig_cur->origin_next) {
        if (orig_cur->origin_next==memb) {
          orig_cur->origin_next=memb->origin_next;
          return; /* just drop the element from the origin list */
        }
      }
    }
  }
  /* if we got here, cur->next was null. Still have to check the origin_next list */
  for (orig_cur=cur; orig_cur->origin_next!=NULL; orig_cur=orig_cur->origin_next) {
    if (orig_cur->origin_next==memb) {
      orig_cur->origin_next=memb->origin_next;
      return; /* just drop the element from the origin list */
    }
  }
}

TR_NAME *tr_comm_memb_get_realm_id(TR_COMM_MEMB *memb)
{
  if (memb->rp!=NULL)
    return tr_rp_realm_get_id(memb->rp);
  else
    return tr_idp_realm_get_id(memb->idp);
}

/* find a membership from any origin */
TR_COMM_MEMB *tr_comm_table_find_memb(TR_COMM_TABLE *ctab, TR_NAME *realm, TR_NAME *comm)
{
  TR_COMM_MEMB *cur=NULL;
  TR_NAME *cur_realm_name=NULL;

  for (cur=ctab->memberships; cur!=NULL; cur=cur->next) {
    cur_realm_name=tr_comm_memb_get_realm_id(cur);
    if (cur_realm_name==NULL) {
      tr_warning("tr_comm_table_find: encountered realm with no name.");
      continue;
    }
    if ((0==tr_name_cmp(realm, cur_realm_name)) &&
        (0==tr_name_cmp(comm, tr_comm_get_id(tr_comm_memb_get_comm(cur))))) {
      return cur;
    }
  }
  return NULL;
}

/* find a membership from a particular origin */
TR_COMM_MEMB *tr_comm_table_find_memb_origin(TR_COMM_TABLE *ctab, TR_NAME *realm, TR_NAME *comm, TR_NAME *origin)
{
  TR_NAME *cur_orig=NULL;
  TR_COMM_MEMB *cur=tr_comm_table_find_memb(ctab, realm, comm);
  if (cur==NULL)
    return NULL; /* no match */

  /* had a match for comm/realm; find origin match */
  while (cur!=NULL) {
    if (((origin==NULL) && (cur_orig==NULL)) ||
        ((origin!=NULL) && (cur_orig!=NULL) && (0==tr_name_cmp(origin, cur_orig))))
      return cur; /* found a match */
    cur=cur->origin_next;
  }
  return NULL; /* no match */
}


/* find an idp membership regardless of its origin */
TR_COMM_MEMB *tr_comm_table_find_idp_memb(TR_COMM_TABLE *ctab, TR_NAME *realm, TR_NAME *comm)
{
  TR_COMM_MEMB *cur=NULL;
  TR_IDP_REALM *idp_realm=NULL;

  for (cur=ctab->memberships; cur!=NULL; cur=cur->next) {
    idp_realm=tr_comm_memb_get_idp_realm(cur);
    if (idp_realm==NULL)
      continue; /* was not an idp */

    if ((0==tr_name_cmp(realm, idp_realm->realm_id)) &&
        (0==tr_name_cmp(comm, tr_comm_get_id(tr_comm_memb_get_comm(cur))))) {
      return cur;
    }
  }
  return NULL;
}

/* find an idp membership from a particular origin */
TR_COMM_MEMB *tr_comm_table_find_idp_memb_origin(TR_COMM_TABLE *ctab, TR_NAME *realm, TR_NAME *comm, TR_NAME *origin)
{
  TR_NAME *cur_orig=NULL;
  TR_COMM_MEMB *cur=tr_comm_table_find_idp_memb(ctab, realm, comm);
  if (cur==NULL)
    return NULL; /* no match */

  /* had a match for comm/realm; find origin match */
  while (cur!=NULL) {
    cur_orig=tr_comm_memb_get_origin(cur);
    if (((origin==NULL) && (cur_orig==NULL)) ||
        ((origin!=NULL) && (cur_orig!=NULL) && (0==tr_name_cmp(origin, cur_orig))))
      return cur; /* found a match */
    cur=cur->origin_next;
  }
  return NULL; /* no match */
}

/* find an rp membership from any origin */
TR_COMM_MEMB *tr_comm_table_find_rp_memb(TR_COMM_TABLE *ctab, TR_NAME *realm, TR_NAME *comm)
{
  TR_COMM_MEMB *cur=NULL;
  TR_RP_REALM *rp_realm=NULL;

  for (cur=ctab->memberships; cur!=NULL; cur=cur->next) {
    rp_realm=tr_comm_memb_get_rp_realm(cur);
    if (rp_realm==NULL)
      continue; /* was not an rp */

    if ((0==tr_name_cmp(realm, tr_rp_realm_get_id(rp_realm))) &&
        (0==tr_name_cmp(comm, tr_comm_get_id(tr_comm_memb_get_comm(cur))))) {
      return cur;
    }
  }
  return NULL;
}

/* find an rp membership from a particular origin */
TR_COMM_MEMB *tr_comm_table_find_rp_memb_origin(TR_COMM_TABLE *ctab, TR_NAME *realm, TR_NAME *comm, TR_NAME *origin)
{
  TR_NAME *cur_orig=NULL;
  TR_COMM_MEMB *cur=tr_comm_table_find_rp_memb(ctab, realm, comm);
  if (cur==NULL)
    return NULL; /* no match */

  /* had a match for comm/realm; find origin match */
  while (cur!=NULL) {
    cur_orig=tr_comm_memb_get_origin(cur);
    if (((origin==NULL) && (cur_orig==NULL)) ||
        ((origin!=NULL) && (cur_orig!=NULL) && (0==tr_name_cmp(origin, cur_orig))))
      return cur; /* found a match */
    cur=cur->origin_next;
  }
  return NULL; /* no match */
}

TR_COMM *tr_comm_table_find_comm(TR_COMM_TABLE *ctab, TR_NAME *comm_id)
{
  return tr_comm_lookup(ctab->comms, comm_id);
}

void tr_comm_table_add_comm(TR_COMM_TABLE *ctab, TR_COMM *new)
{
  tr_comm_add(ctab->comms, new);
  if (ctab->comms!=NULL)
    talloc_steal(ctab, ctab->comms); /* make sure it's in the right context */
}

void tr_comm_table_remove_comm(TR_COMM_TABLE *ctab, TR_COMM *comm)
{
  tr_comm_remove(ctab->comms, comm);
}

TR_RP_REALM *tr_comm_table_find_rp_realm(TR_COMM_TABLE *ctab, TR_NAME *realm_id)
{
  return tr_rp_realm_lookup(ctab->rp_realms, realm_id);
}

void tr_comm_table_add_rp_realm(TR_COMM_TABLE *ctab, TR_RP_REALM *new)
{
  tr_rp_realm_add(ctab->rp_realms, new);
  if (ctab->rp_realms!=NULL)
    talloc_steal(ctab, ctab->rp_realms); /* make sure it's in the right context */
}

void tr_comm_table_remove_rp_realm(TR_COMM_TABLE *ctab, TR_RP_REALM *realm)
{
  tr_rp_realm_remove(ctab->rp_realms, realm);
}

TR_IDP_REALM *tr_comm_table_find_idp_realm(TR_COMM_TABLE *ctab, TR_NAME *realm_id)
{
  return tr_idp_realm_lookup(ctab->idp_realms, realm_id);
}

void tr_comm_table_add_idp_realm(TR_COMM_TABLE *ctab, TR_IDP_REALM *new)
{
  tr_idp_realm_add(ctab->idp_realms, new);
  if (ctab->idp_realms!=NULL)
    talloc_steal(ctab, ctab->idp_realms); /* make sure it's in the right context */
}

void tr_comm_table_remove_idp_realm(TR_COMM_TABLE *ctab, TR_IDP_REALM *realm)
{
  tr_idp_realm_remove(ctab->idp_realms, realm);
}


/* how many communities in the table? */
size_t tr_comm_table_size(TR_COMM_TABLE *ctab)
{
  size_t count=0;
  TR_COMM *this=ctab->comms;
  while(this!=NULL) {
    this=this->next;
    count++;
  }
  return count;
}

/* clean up unreferenced realms, etc */
void tr_comm_table_sweep(TR_COMM_TABLE *ctab)
{
  tr_rp_realm_sweep(ctab->rp_realms);
  tr_idp_realm_sweep(ctab->idp_realms);
  tr_comm_sweep(ctab->comms);
}


const char *tr_realm_role_to_str(TR_REALM_ROLE role)
{
  switch(role) {
  case TR_ROLE_IDP:
    return "idp";
  case TR_ROLE_RP:
    return "rp";
  default:
    return NULL;
  }
}

TR_REALM_ROLE tr_realm_role_from_str(const char *s)
{
  if (strcmp(s, "idp")==0)
    return TR_ROLE_IDP;
  if (strcmp(s, "rp")==0)
    return TR_ROLE_RP;
  return TR_ROLE_UNKNOWN;
}

static char *tr_comm_table_append_provenance(char *ctable_s, json_t *prov)
{
  const char *s=NULL;
  char *tmp=NULL;
  size_t ii=0;

  for (ii=0; ii<json_array_size(prov); ii++) {
    s=json_string_value(json_array_get(prov, ii));
    if (s!=NULL) {
      tmp=talloc_asprintf_append(ctable_s, "%s%s", s, ((ii + 1) == json_array_size(prov)) ? "" : ", ");
      if (tmp==NULL)
        return NULL;
      ctable_s=tmp;
    }
  }
  return ctable_s;
}

char *tr_comm_table_to_str(TALLOC_CTX *mem_ctx, TR_COMM_TABLE *ctab)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  char *ctable_s=NULL;
  char *tmp=NULL;
#define append_on_success_helper(tab,tmp,expr) if(NULL==((tmp)=(expr))){(tab)=NULL;goto cleanup;}(tab)=(tmp)

  TR_COMM_MEMB *p1=NULL; /* for walking the main list */
  TR_COMM_MEMB *p2=NULL; /* for walking the same-origin lists */

  ctable_s=talloc_asprintf(tmp_ctx, ">> Membership table start <<\n");
  if (ctable_s==NULL)
    goto cleanup;

  for (p1=ctab->memberships; p1!=NULL; p1=p1->next) {
    append_on_success_helper(
        ctable_s, tmp,
        talloc_asprintf_append(ctable_s, "* %s %s/%s\n  %s (%p) - prov: ",
                               tr_realm_role_to_str(tr_comm_memb_get_role(p1)),
                               tr_comm_memb_get_realm_id(p1)->buf,
                               tr_comm_get_id(tr_comm_memb_get_comm(p1))->buf,
                               (tr_comm_memb_get_origin(p1)==NULL)?"null origin":(tr_comm_memb_get_origin(p1)->buf),
                               p1));

    append_on_success_helper(ctable_s, tmp, tr_comm_table_append_provenance(ctable_s, p1->provenance));

    append_on_success_helper(ctable_s, tmp, talloc_strdup_append_buffer(ctable_s, "\n"));

    for (p2=p1->origin_next; p2!=NULL; p2=p2->origin_next) {
      append_on_success_helper(
          ctable_s, tmp,
          talloc_asprintf_append(ctable_s, "  %s (%p) - prov: ",
          (tr_comm_memb_get_origin(p2)==NULL)?"null origin":(tr_comm_memb_get_origin(p2)->buf),
              p2));
      append_on_success_helper(ctable_s, tmp, tr_comm_table_append_provenance(ctable_s, p2->provenance));
      append_on_success_helper(ctable_s, tmp, talloc_strdup_append_buffer(ctable_s, "\n"));
    }
    append_on_success_helper(ctable_s, tmp, talloc_strdup_append_buffer(ctable_s, "\n"));
  }

cleanup:
  if (ctable_s!=NULL)
    talloc_steal(mem_ctx, ctable_s);

  talloc_free(tmp_ctx);
  return ctable_s;
}

void tr_comm_table_print(FILE *f, TR_COMM_TABLE *ctab)
{
  char *s=tr_comm_table_to_str(NULL, ctab);
  if (s!=NULL) {
    tr_debug("%s", s);
    talloc_free(s);
  }
}