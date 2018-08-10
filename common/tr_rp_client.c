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

#include <talloc.h>
#include <tr_rp_client.h>
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

