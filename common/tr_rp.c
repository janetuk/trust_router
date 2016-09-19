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
#include <trust_router/tr_name.h>
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
    client->filter=NULL;
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

TR_RP_CLIENT *tr_rp_client_add(TR_RP_CLIENT *clients, TR_RP_CLIENT *new)
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

int tr_rp_client_set_filter(TR_RP_CLIENT *client, TR_FILTER *filt)
{
  if (client->filter!=NULL)
    tr_filter_free(client->filter);
  client->filter=filt;
  talloc_steal(client, filt);
  return 0; /* success */
}

TR_RP_CLIENT *tr_rp_client_lookup(TR_RP_CLIENT *rp_clients, TR_NAME *gss_name)
{
  TR_RP_CLIENT *rp = NULL;

  if ((!rp_clients) || (!gss_name)) {
    tr_debug("tr_rp_client_lookup: Bad parameters.");
    return NULL;
  }

  for (rp = rp_clients; NULL != rp; rp = rp->next) {
    if (tr_gss_names_matches(rp->gss_names, gss_name))
      return rp;
  } 
  return NULL;
}

/* talloc note: lists of idp realms should be assembled using
 * tr_idp_realm_add(). This will put all of the elements in the
 * list, other than the head, as children of the head context.
 * The head can then be placed in whatever context is desired. */

static TR_RP_REALM *tr_rp_realm_tail(TR_RP_REALM *realm)
{
  while (realm!=NULL)
    realm=realm->next;
  return realm;
}

/* for correct behavior, call like: rp_realms=tr_rp_realm_add(rp_realms, new_realm); */
TR_RP_REALM *tr_rp_realm_add(TR_RP_REALM *head, TR_RP_REALM *new)
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
