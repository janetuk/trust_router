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

#include <talloc.h>
#include <time.h>

#include <tr_aaa_server.h>
#include <tr_name_internal.h>
#include <tr_idp.h>
#include <tr_config.h>
#include <tr_debug.h>

/* fills in shared if pointer not null */
TR_AAA_SERVER *tr_idp_aaa_server_lookup(TR_IDP_REALM *idp_realms, TR_NAME *idp_realm_name, TR_NAME *comm, int *shared_out)
{
  TR_IDP_REALM *idp = NULL;

  for (idp = idp_realms; idp != NULL; idp = idp->next) {
    if (!tr_name_cmp(idp_realm_name, idp->realm_id)) {
      /* TBD -- check that the community is one of the APCs for the IDP */
      break;
    }
  }
  if (idp) {
    if (shared_out!=NULL)
      *shared_out=idp->shared_config;
    return idp->aaa_servers;
  } else 
    return NULL;
}

TR_AAA_SERVER *tr_default_server_lookup(TR_AAA_SERVER *default_servers, TR_NAME *comm)
{
  if (!default_servers)
    return NULL;

  return(default_servers);
}

static int tr_idp_realm_destructor(void *obj)
{
  TR_IDP_REALM *idp=talloc_get_type_abort(obj, TR_IDP_REALM);
  if (idp->realm_id!=NULL)
    tr_free_name(idp->realm_id);
  return 0;
}

/* talloc note: lists of idp realms should be assembled using
 * tr_idp_realm_add(). This will put all of the elements in the
 * list, other than the head, as children of the head context.
 * The head can then be placed in whatever context is desired. */
TR_IDP_REALM *tr_idp_realm_new(TALLOC_CTX *mem_ctx)
{
  TR_IDP_REALM *idp=talloc(mem_ctx, TR_IDP_REALM);
  if (idp!=NULL) {
    idp->next=NULL;
    idp->comm_next=NULL;
    idp->realm_id=NULL;
    idp->shared_config=0;
    idp->aaa_servers=NULL;
    idp->apcs=NULL;
    idp->origin=TR_REALM_LOCAL;
    idp->refcount=0;
    talloc_set_destructor((void *)idp, tr_idp_realm_destructor);
  }
  return idp;
}

void tr_idp_realm_free(TR_IDP_REALM *idp)
{
  talloc_free(idp);
}

TR_NAME *tr_idp_realm_get_id(TR_IDP_REALM *idp)
{
  if (idp==NULL)
    return NULL;
  
  return idp->realm_id;
}

TR_NAME *tr_idp_realm_dup_id(TR_IDP_REALM *idp)
{
  if (idp==NULL)
    return NULL;
  
  return tr_dup_name(tr_idp_realm_get_id(idp));
}

void tr_idp_realm_set_id(TR_IDP_REALM *idp, TR_NAME *id)
{
  if (idp->realm_id!=NULL)
    tr_free_name(idp->realm_id);
  idp->realm_id=id;
}

void tr_idp_realm_set_apcs(TR_IDP_REALM *idp, TR_APC *apc)
{
  if (idp->apcs!=NULL)
    tr_apc_free(idp->apcs);
  idp->apcs=apc;
  talloc_steal(idp, apc);
}

TR_APC *tr_idp_realm_get_apcs(TR_IDP_REALM *idp)
{
  return idp->apcs;
}

TR_IDP_REALM *tr_idp_realm_lookup(TR_IDP_REALM *idp_realms, TR_NAME *idp_name)
{
  TR_IDP_REALM *idp = NULL;

  if (!idp_name) {
    tr_debug("tr_idp_realm_lookup: Bad parameters.");
    return NULL;
  }

  for (idp=idp_realms; NULL!=idp; idp=idp->next) {
    if (0==tr_name_cmp(tr_idp_realm_get_id(idp), idp_name))
      return idp;
  } 
  return NULL;
}


static TR_IDP_REALM *tr_idp_realm_tail(TR_IDP_REALM *idp)
{
  if (idp==NULL)
    return NULL;

  while (idp->next!=NULL)
    idp=idp->next;
  return idp;
}

/* do not call directly, use the tr_idp_realm_add() macro */
TR_IDP_REALM *tr_idp_realm_add_func(TR_IDP_REALM *head, TR_IDP_REALM *new)
{
  if (head==NULL)
    head=new;
  else {
    tr_idp_realm_tail(head)->next=new;
    while (new!=NULL) {
      talloc_steal(head, new); /* put it in the right context */
      new=new->next;
    }
  }
  return head;
}

/* use the macro */
TR_IDP_REALM *tr_idp_realm_remove_func(TR_IDP_REALM *head, TR_IDP_REALM *remove)
{
  TALLOC_CTX *list_ctx=talloc_parent(head);
  TR_IDP_REALM *this=NULL;

  if (head==NULL)
    return NULL;

  if (head==remove) {
    /* if we're removing the head, put the next element (if present) into the context
     * the list head was in. */
    head=head->next;
    if (head!=NULL) {
      talloc_steal(list_ctx, head);
      /* now put all the other elements in the context of the list head */
      for (this=head->next; this!=NULL; this=this->next)
        talloc_steal(head, this);
    }
  } else {
    /* not removing the head; no need to play with contexts */
    for (this=head; this->next!=NULL; this=this->next) {
      if (this->next==remove) {
        this->next=remove->next;
        break;
      }
    }
  }
  return head;
}

int tr_idp_realm_apc_count(TR_IDP_REALM *idp)
{
  int ii=0;
  TR_APC *apc=idp->apcs;
  while (apc!=NULL) {
    apc=apc->next;
    ii++;
  }
  return ii;
}

int tr_idp_realm_aaa_server_count(TR_IDP_REALM *idp)
{
  int ii=0;
  TR_AAA_SERVER *aaa=idp->aaa_servers;
  while (aaa!=NULL) {
    aaa=aaa->next;
    ii++;
  }
  return ii;
}

void tr_idp_realm_incref(TR_IDP_REALM *realm)
{
  realm->refcount++;
}

void tr_idp_realm_decref(TR_IDP_REALM *realm)
{
  if (realm->refcount>0)
    realm->refcount--;
}

/* remove any with zero refcount 
 * Call via macro. */
TR_IDP_REALM *tr_idp_realm_sweep_func(TR_IDP_REALM *head)
{
  TR_IDP_REALM *idp=NULL;
  TR_IDP_REALM *old_next=NULL;

  if (head==NULL)
    return NULL;

  while ((head!=NULL) && (head->refcount==0)) {
    idp=head; /* keep a pointer so we can remove it */
    tr_idp_realm_remove(head, idp); /* use this to get talloc contexts right */
    tr_idp_realm_free(idp);
  }

  if (head==NULL)
    return NULL;

  /* Will not remove the head here, that has already been done.*/
  for (idp=head; (idp!=NULL) && (idp->next!=NULL); idp=idp->next) {
    if (idp->next->refcount==0) {
      old_next=idp->next;
      tr_idp_realm_remove(head, idp->next); /* changes idp->next, may make it NULL */
      tr_idp_realm_free(old_next);
    }
  }

  return head;
}

