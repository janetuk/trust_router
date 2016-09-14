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

#include <jansson.h>
#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <tr_debug.h>

static int trp_req_destructor(void *object)
{
  TRP_REQ *req=talloc_get_type_abort(object, TRP_REQ);
  
  /* clean up TR_NAME data, which are not managed by talloc */
  if (req->comm != NULL)
    tr_free_name(req->comm);

  if (req->realm != NULL)
    tr_free_name(req->realm);

  if (req->peer != NULL)
    tr_free_name(req->peer);

  return 0;
}

TRP_REQ *trp_req_new(TALLOC_CTX *mem_ctx)
{
  TRP_REQ *new_req=talloc(mem_ctx, TRP_REQ);

  if (new_req != NULL) {
    new_req->comm=NULL;
    new_req->realm=NULL;
    new_req->peer=NULL;
  }

  talloc_set_destructor((void *)new_req, trp_req_destructor);
  return new_req;
}

void trp_req_free(TRP_REQ *req)
{
  if (req!=NULL)
    talloc_free(req);
}

TR_NAME *trp_req_get_comm(TRP_REQ *req)
{
  if (req!=NULL)
    return req->comm;
  else
    return NULL;
}

void trp_req_set_comm(TRP_REQ *req, TR_NAME *comm)
{
  if (req)
    req->comm=comm;
}

TR_NAME *trp_req_get_realm(TRP_REQ *req)
{
  if (req!=NULL)
    return req->realm;
  else
    return NULL;
}


void trp_req_set_realm(TRP_REQ *req, TR_NAME *realm)
{
  if (req)
    req->realm=realm;
}

TR_NAME *trp_req_get_peer(TRP_REQ *req)
{
  if (req!=NULL)
    return req->peer;
  else
    return NULL;
}


void trp_req_set_peer(TRP_REQ *req, TR_NAME *peer)
{
  if (req)
    req->peer=peer;
}

/* Defines what we use as a wildcard for realm or community name.
 * Must not be a valid name for either of those. Currently, we
 * use the empty string. */
static int trp_req_name_is_wildcard(TR_NAME *name)
{
  return (name!=NULL) && (name->len==0);
}

int trp_req_is_wildcard(TRP_REQ *req)
{
  return (req!=NULL) && trp_req_name_is_wildcard(req->comm) && trp_req_name_is_wildcard(req->realm);
}

TRP_RC trp_req_make_wildcard(TRP_REQ *req)
{
  if (req==NULL)
    return TRP_BADARG;

  req->comm=tr_new_name("");
  if (req->comm==NULL)
    return TRP_NOMEM;

  req->realm=tr_new_name("");
  if (req->realm==NULL) {
    tr_free_name(req->comm);
    req->comm=NULL;
    return TRP_NOMEM;
  }

  return TRP_SUCCESS;
}
