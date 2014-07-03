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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <talloc.h>

#include <trust_router/tid.h>
#include <jansson.h>

static int destroy_tid_req(TID_REQ *req)
{
  if (req->json_references)
    json_decref(req->json_references);
  return 0;
}

TID_REQ *tid_req_new()
{
  TID_REQ *req = talloc_zero(NULL, TID_REQ);
  if(!req)
    return NULL;
  talloc_set_destructor(req, destroy_tid_req);
  req->json_references = json_array();
  assert(req->json_references);
  req->conn = -1;
  return req;
}

TID_REQ *tid_req_get_next_req(TID_REQ *req)
{
  return(req->next_req);
}

void tid_req_set_next_req(TID_REQ *req, TID_REQ *next_req)
{
  req->next_req = next_req;
}

int tid_req_get_resp_sent(TID_REQ *req)
{
  return(req->resp_sent);
}

void tid_req_set_resp_sent(TID_REQ *req, int resp_sent)
{
  req->resp_sent = resp_sent;
}

int tid_req_get_conn(TID_REQ *req)
{
  return(req->conn);
}

void tid_req_set_conn(TID_REQ *req, int conn)
{
  req->conn = conn;
}

gss_ctx_id_t tid_req_get_gssctx(TID_REQ *req)
{
  return(req->gssctx);
}

void tid_req_set_gssctx(TID_REQ *req, gss_ctx_id_t gssctx)
{
  req->gssctx = gssctx;
}

int tid_req_get_resp_rcvd(TID_REQ *req)
{
  return(req->resp_rcvd);
}

void tid_req_set_resp_rcvd(TID_REQ *req, int resp_rcvd)
{
  req->resp_rcvd = resp_rcvd;
}

TR_NAME *tid_req_get_rp_realm(TID_REQ *req)
{
  return(req->rp_realm);
}

void tid_req_set_rp_realm(TID_REQ *req, TR_NAME *rp_realm)
{
  req->rp_realm = rp_realm;
}

TR_NAME *tid_req_get_realm(TID_REQ *req)
{
  return(req->realm);
}

void tid_req_set_realm(TID_REQ *req, TR_NAME *realm)
{
  req->realm = realm;
}

TR_NAME *tid_req_get_comm(TID_REQ *req)
{
  return(req->comm);
}

void tid_req_set_comm(TID_REQ *req, TR_NAME *comm)
{
  req->comm = comm;
}

TR_NAME *tid_req_get_orig_coi(TID_REQ *req)
{
  return(req->orig_coi);
}

void tid_req_set_rp_orig_coi(TID_REQ *req, TR_NAME *orig_coi)
{
  req->orig_coi = orig_coi;
}

TIDC_RESP_FUNC *tid_req_get_resp_func(TID_REQ *req)
{
  return(req->resp_func);
}

void tid_req_set_resp_func(TID_REQ *req, TIDC_RESP_FUNC *resp_func)
{
  req->resp_func = resp_func;
}

void *tid_req_get_cookie(TID_REQ *req)
{
  return(req->cookie);
}

void tid_req_set_cookie(TID_REQ *req, void *cookie)
{
  req->cookie = cookie;
}

TID_REQ *tid_dup_req (TID_REQ *orig_req) 
{
  TID_REQ *new_req = NULL;

  if (NULL == (new_req = malloc(sizeof(TID_REQ)))) {
    fprintf(stderr, "tid_dup_req: Can't allocated duplicate request.\n");
    return NULL;
  }

  /* Memcpy for flat fields, not valid until names are duped. */
  memcpy(new_req, orig_req, sizeof(TID_REQ));
  json_incref(new_req->json_references);
  
  if ((NULL == (new_req->rp_realm = tr_dup_name(orig_req->rp_realm))) ||
      (NULL == (new_req->realm = tr_dup_name(orig_req->realm))) ||
      (NULL == (new_req->comm = tr_dup_name(orig_req->comm)))) {
	fprintf(stderr, "tid_dup_req: Can't duplicate request (names).\n");
  }

  if (orig_req->orig_coi) {
    if (NULL == (new_req->orig_coi = tr_dup_name(orig_req->orig_coi))) {
      fprintf(stderr, "tid_dup_req: Can't duplicate request (orig_coi).\n");
    }
  }
  
  return new_req;
}


void tid_req_cleanup_json( TID_REQ *req, json_t *ref)
{
  (void) json_array_append_new(req->json_references, ref);
}

void tid_req_free(TID_REQ *req)
{
  talloc_free(req);
}
