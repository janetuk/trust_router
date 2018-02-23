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

#include <tr.h>
#include <tr_name_internal.h>
#include <tr_gss.h>
#include <tr_config.h>
#include <tr_rp.h>
#include <tr_debug.h>

static int tr_rp_client_destructor(void *obj)
{
  return 0;
}

TR_RP_CLIENT *tr_rp_client_new(TALLOC_CTX *mem_ctx)
{
  TR_RP_CLIENT *client=talloc(mem_ctx, TR_RP_CLIENT);

  if (client!=NULL) {
    client->next=NULL;
    client->comm_next=NULL;
    client->gss_names=NULL;
    client->filters=NULL;
    talloc_set_destructor((void *)client, tr_rp_client_destructor);
  }
  return client;
}

void tr_rp_client_free(TR_RP_CLIENT *client)
{
  talloc_free(client);
}

static TR_RP_CLIENT *tr_rp_client_tail(TR_RP_CLIENT *client)
{
  if (client==NULL)
    return NULL;

  while (client->next!=NULL)
    client=client->next;
  return client;
}

/* do not call directly, use the tr_rp_client_add() macro */
TR_RP_CLIENT *tr_rp_client_add_func(TR_RP_CLIENT *clients, TR_RP_CLIENT *new)
{
  if (clients==NULL)
    clients=new;
  else {
    tr_rp_client_tail(clients)->next=new;
    while (new!=NULL) {
      talloc_steal(clients, new); /* put it in the right context */
      new=new->next;
    }
  }
  return clients;
}


int tr_rp_client_add_gss_name(TR_RP_CLIENT *rp_client, TR_NAME *gss_name)
{
  return tr_gss_names_add(rp_client->gss_names, gss_name);
}

int tr_rp_client_set_filters(TR_RP_CLIENT *client, TR_FILTER_SET *filts)
{
  if (client->filters!=NULL)
    tr_filter_set_free(client->filters);
  client->filters=filts;
  talloc_steal(client, filts);
  return 0; /* success */
}

TR_RP_CLIENT_ITER *tr_rp_client_iter_new(TALLOC_CTX *memctx)
{
  return talloc(memctx, TR_RP_CLIENT_ITER);
}

void tr_rp_client_iter_free(TR_RP_CLIENT_ITER *iter)
{
  talloc_free(iter);
}

TR_RP_CLIENT *tr_rp_client_iter_first(TR_RP_CLIENT_ITER *iter, TR_RP_CLIENT *rp_clients)
{
  if (!iter) {
    tr_err("tr_rp_client_iter_first: Iterator is null, failing.");
    return NULL;
  }
  *iter=rp_clients;
  return *iter;
}

TR_RP_CLIENT *tr_rp_client_iter_next(TR_RP_CLIENT_ITER *iter)
{
  if (*iter)
    *iter=(*iter)->next;
  return *iter;
}

/**
 * Find a client associated with a GSS name. It's possible there are other clients that match as well.
 *
 * @param rp_clients List of RP clients to search
 * @param gss_name GSS name to search for
 * @return Borrowed reference to an RP client linked to the GSS name
 */
TR_RP_CLIENT *tr_rp_client_lookup(TR_RP_CLIENT *rp_clients, TR_NAME *gss_name)
{
  TR_RP_CLIENT_ITER *iter=tr_rp_client_iter_new(NULL);
  TR_RP_CLIENT *client=NULL;

  if (iter==NULL) {
    tr_err("tr_rp_client_lookup: Unable to allocate iterator");
    return NULL;
  }
  for (client=tr_rp_client_iter_first(iter, rp_clients); client != NULL; client=tr_rp_client_iter_next(iter)) {
    if (tr_gss_names_matches(client->gss_names, gss_name))
      break;
  }
  tr_rp_client_iter_free(iter);
  return client;
}

TR_RP_REALM *tr_rp_realm_lookup(TR_RP_REALM *rp_realms, TR_NAME *rp_name)
{
  TR_RP_REALM *rp = NULL;

  if (!rp_name) {
    tr_debug("tr_rp_realm_lookup: Bad parameters.");
    return NULL;
  }

  for (rp=rp_realms; NULL!=rp; rp=rp->next) {
    if (0==tr_name_cmp(tr_rp_realm_get_id(rp), rp_name))
      return rp;
  } 
  return NULL;
}

static int tr_rp_realm_destructor(void *obj)
{
  TR_RP_REALM *rp=talloc_get_type_abort(obj, TR_RP_REALM);
  if (rp->realm_id!=NULL)
    tr_free_name(rp->realm_id);
  return 0;
}

TR_RP_REALM *tr_rp_realm_new(TALLOC_CTX *mem_ctx)
{
  TR_RP_REALM *rp=talloc(mem_ctx, TR_RP_REALM);
  if (rp!=NULL) {
    rp->next=NULL;
    rp->realm_id=NULL;
    rp->refcount=0;
    talloc_set_destructor((void *)rp, tr_rp_realm_destructor);
  }
  return rp;
}

void tr_rp_realm_free(TR_RP_REALM *rp)
{
  talloc_free(rp);
}

/* talloc note: lists of idp realms should be assembled using
 * tr_idp_realm_add(). This will put all of the elements in the
 * list, other than the head, as children of the head context.
 * The head can then be placed in whatever context is desired. */

static TR_RP_REALM *tr_rp_realm_tail(TR_RP_REALM *realm)
{
  if (realm==NULL)
    return NULL;

  while (realm->next!=NULL)
    realm=realm->next;
  return realm;
}

/* for correct behavior, call like: rp_realms=tr_rp_realm_add_func(rp_realms, new_realm);
 * or better yet, use the macro */
TR_RP_REALM *tr_rp_realm_add_func(TR_RP_REALM *head, TR_RP_REALM *new)
{
  if (head==NULL)
    head=new;
  else {
    tr_rp_realm_tail(head)->next=new;
    while (new!=NULL) {
      talloc_steal(head, new); /* put it in the right context */
      new=new->next;
    }
  }
  return head;
}

/* use the macro */
TR_RP_REALM *tr_rp_realm_remove_func(TR_RP_REALM *head, TR_RP_REALM *remove)
{
  TALLOC_CTX *list_ctx=talloc_parent(head);
  TR_RP_REALM *this=NULL;

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

void tr_rp_realm_incref(TR_RP_REALM *realm)
{
  realm->refcount++;
}

void tr_rp_realm_decref(TR_RP_REALM *realm)
{
  if (realm->refcount>0)
    realm->refcount--;
}

/* remove any with zero refcount 
 * Call via macro. */
TR_RP_REALM *tr_rp_realm_sweep_func(TR_RP_REALM *head)
{
  TR_RP_REALM *rp=NULL;
  TR_RP_REALM *old_next=NULL;

  if (head==NULL)
    return NULL;

  while ((head!=NULL) && (head->refcount==0)) {
    rp=head; /* keep a pointer so we can remove it */
    tr_rp_realm_remove(head, rp); /* use this to get talloc contexts right */
    tr_rp_realm_free(rp);
  }

  if (head==NULL)
    return NULL;

  /* will not remove the head here, that has already been done */
  for (rp=head; (rp!=NULL) && (rp->next!=NULL); rp=rp->next) {
    if (rp->next->refcount==0) {
      old_next=rp->next;
      tr_rp_realm_remove(head, rp->next); /* changes rp->next, may make it null */
      tr_rp_realm_free(old_next);
    }
  }

  return head;
}

TR_NAME *tr_rp_realm_get_id(TR_RP_REALM *rp)
{
  if (rp==NULL)
    return NULL;

  return rp->realm_id;
}

TR_NAME *tr_rp_realm_dup_id(TR_RP_REALM *rp)
{
  if (rp==NULL)
    return NULL;

  return tr_dup_name(tr_rp_realm_get_id(rp));
}

void tr_rp_realm_set_id(TR_RP_REALM *rp, TR_NAME *id)
{
  if (rp->realm_id!=NULL)
    tr_free_name(rp->realm_id);
  rp->realm_id=id;
}

char *tr_rp_realm_to_str(TALLOC_CTX *mem_ctx, TR_RP_REALM *rp)
{
  return talloc_asprintf(mem_ctx,
                         "RP realm: \"%.*s\"\n",
                         rp->realm_id->len, rp->realm_id->buf);
}
