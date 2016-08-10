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

#include <trust_router/tr_name.h>
#include <tr_idp.h>
#include <tr_config.h>

static int tr_aaa_server_destructor(void *obj)
{
  TR_AAA_SERVER *aaa=talloc_get_type_abort(obj, TR_AAA_SERVER);
  if (aaa->hostname!=NULL)
    tr_free_name(aaa->hostname);
  return 0;
}

TR_AAA_SERVER *tr_aaa_server_new(TALLOC_CTX *mem_ctx, TR_NAME *hostname)
{
  TR_AAA_SERVER *aaa=talloc(mem_ctx, TR_AAA_SERVER);
  if (aaa!=NULL) {
    aaa->hostname=hostname;
    talloc_set_destructor((void *)aaa, tr_aaa_server_destructor);
  }
  return aaa;
}

void tr_aaa_server_free(TR_AAA_SERVER *aaa)
{
  talloc_free(aaa);
}

TR_AAA_SERVER *tr_idp_aaa_server_lookup(TR_IDP_REALM *idp_realms, TR_NAME *idp_realm_name, TR_NAME *comm)
{
  TR_IDP_REALM *idp = NULL;

  for (idp = idp_realms; idp != NULL; idp = idp->next) {
    if (!tr_name_cmp(idp_realm_name, idp->realm_id)) {
      /* TBD -- check that the community is one of the APCs for the IDP */
      break;
    }
  }
  if (idp)
    return idp->aaa_servers;
  else 
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
    talloc_set_destructor((void *)idp, tr_idp_realm_destructor);
  }
  return idp;
}
