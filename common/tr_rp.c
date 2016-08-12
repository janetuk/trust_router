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
#include <tr_config.h>
#include <tr_rp.h>
#include <tr_debug.h>

TR_RP_CLIENT *tr_rp_client_lookup(TR_RP_CLIENT *rp_clients, TR_NAME *gss_name) {
  TR_RP_CLIENT *rp = NULL;
  int i = 0;

  if ((!rp_clients) || (!gss_name)) {
    tr_debug("tr_rp_client_lookup: Bad parameters.");
    return NULL;
  }

  for (rp = rp_clients; NULL != rp; rp = rp->next) {
    for (i = 0; ((i < TR_MAX_GSS_NAMES) && (NULL != (rp->gss_names[i]))); i++) {
	if (!tr_name_cmp(gss_name, rp->gss_names[i])) {
	return rp;
      }
    }
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
