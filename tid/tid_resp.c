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

#include <trust_router/tr_dh.h>
#include <tid_internal.h>

static int tid_resp_destructor(void *obj)
{
  TID_RESP *resp=talloc_get_type_abort(obj, TID_RESP);
  if (resp->err_msg!=NULL)
    tr_free_name(resp->err_msg);
  if (resp->rp_realm!=NULL)
    tr_free_name(resp->rp_realm);
  if (resp->realm!=NULL)
    tr_free_name(resp->realm);
  if (resp->comm!=NULL)
    tr_free_name(resp->comm);
  if (resp->orig_coi!=NULL)
    tr_free_name(resp->orig_coi);
  if (resp->request_id!=NULL)
    tr_free_name(resp->request_id);
  return 0;
}

TID_RESP *tid_resp_new(TALLOC_CTX *mem_ctx)
{
  TID_RESP *resp=talloc(mem_ctx, TID_RESP);
  if (resp!=NULL) {
    resp->result=TID_ERROR;
    resp->err_msg=NULL;
    resp->rp_realm=NULL;
    resp->realm=NULL;
    resp->comm=NULL;
    resp->cons=NULL;
    resp->orig_coi=NULL;
    resp->servers=NULL;
    resp->request_id=NULL;
    resp->error_path=NULL;
    talloc_set_destructor((void *)resp, tid_resp_destructor);
  }
  return resp;
}

void tid_resp_free(TID_RESP *resp)
{
  if (resp)
    talloc_free(resp);
}

TID_RESP *tid_resp_dup(TALLOC_CTX *mem_ctx, TID_RESP *resp)
{
  TID_RESP *newresp=NULL;

  if (resp==NULL)
    return NULL;

  newresp=tid_resp_new(mem_ctx);

  if (NULL!=newresp) {
    newresp->result=resp->result;
    newresp->err_msg=tr_dup_name(resp->err_msg);
    newresp->rp_realm=tr_dup_name(resp->rp_realm);
    newresp->realm=tr_dup_name(resp->realm);
    newresp->comm=tr_dup_name(resp->comm);
    newresp->orig_coi=tr_dup_name(resp->orig_coi);
    newresp->servers=tid_srvr_blk_dup(newresp, resp->servers);
    tid_resp_set_cons(newresp, resp->cons);
    tid_resp_set_error_path(newresp, resp->error_path);
  }
  return newresp;
}

TR_EXPORT int tid_resp_get_result(TID_RESP *resp)
{
  return(resp->result);
}

void tid_resp_set_result(TID_RESP *resp, int result)
{
  resp->result = result;
}

TR_EXPORT TR_NAME *tid_resp_get_err_msg(TID_RESP *resp)
{
  return(resp->err_msg);
}

void tid_resp_set_err_msg(TID_RESP *resp, TR_NAME *err_msg)
{
  if (resp->err_msg!=NULL)
    tr_free_name(resp->err_msg);

  resp->err_msg = err_msg;
}

TR_EXPORT TR_NAME *tid_resp_get_rp_realm(TID_RESP *resp)
{
  return(resp->rp_realm);
}

void tid_resp_set_rp_realm(TID_RESP *resp, TR_NAME *rp_realm)
{
  resp->rp_realm = rp_realm;
}

TR_EXPORT TR_NAME *tid_resp_get_realm(TID_RESP *resp)
{
  return(resp->realm);
}

void tid_resp_set_realm(TID_RESP *resp, TR_NAME *realm)
{
  resp->realm = realm;
}

TR_EXPORT TR_NAME *tid_resp_get_comm(TID_RESP *resp)
{
  return(resp->comm);
}

void tid_resp_set_comm(TID_RESP *resp, TR_NAME *comm)
{
  resp->comm = comm;
}

TR_EXPORT TR_NAME *tid_resp_get_orig_coi(TID_RESP *resp)
{
  return(resp->orig_coi);
}

void tid_resp_set_orig_coi(TID_RESP *resp, TR_NAME *orig_coi)
{
  resp->orig_coi = orig_coi;
}

TR_EXPORT TR_NAME *tid_resp_get_request_id(TID_RESP *resp)
{
  return(resp->request_id);
}

void tid_resp_set_request_id(TID_RESP *resp, TR_NAME *request_id)
{
  resp->request_id = request_id;
}

TR_EXPORT TID_SRVR_BLK *tid_resp_get_server(TID_RESP *resp,
					    size_t index)
{
  TID_SRVR_BLK *this=NULL;
  assert(resp);

  for (this=resp->servers; index>0; index--, this=this->next) {}

  return this;
}

size_t tid_resp_get_num_servers(const TID_RESP *resp)
{
  size_t count=0;
  TID_SRVR_BLK *this=NULL;

  assert(resp!=NULL);
  for (count=0, this=resp->servers; this!=NULL; count++, this=this->next) {}
  return count;
}

static int tid_srvr_blk_destructor(void *obj)
{
  TID_SRVR_BLK *srvr=talloc_get_type_abort(obj, TID_SRVR_BLK);

  if (srvr->key_name!=NULL)
    tr_free_name(srvr->key_name);
  if (srvr->aaa_server_dh!=NULL)
    tr_destroy_dh_params(srvr->aaa_server_dh);
  if (srvr->path!=NULL)
    json_decref((json_t *)(srvr->path));
  return 0;
}

TR_EXPORT TID_SRVR_BLK *tid_srvr_blk_new(TALLOC_CTX *mem_ctx)
{
  TID_SRVR_BLK *srvr=talloc(mem_ctx, TID_SRVR_BLK);

  if (srvr!=NULL) {
    srvr->next=NULL;
    srvr->aaa_server_addr=NULL;
    srvr->key_name=NULL;
    srvr->aaa_server_dh=NULL;
    srvr->key_expiration=(GTimeVal){0};
    srvr->path=NULL;
    talloc_set_destructor((void *)srvr, tid_srvr_blk_destructor);
  }
  return srvr;
}

TR_EXPORT void tid_srvr_blk_free(TID_SRVR_BLK *srvr)
{
  talloc_free(srvr);
}

TR_EXPORT TID_SRVR_BLK *tid_srvr_blk_dup(TALLOC_CTX *mem_ctx, TID_SRVR_BLK *srvr)
{
  TID_SRVR_BLK *new=NULL;

  if (srvr==NULL)
    return NULL;

  new=tid_srvr_blk_new(mem_ctx);
  if (new!=NULL) {
    if (srvr->aaa_server_addr!=NULL)
      new->aaa_server_addr=talloc_strdup(new, srvr->aaa_server_addr);
    new->key_name=tr_dup_name(srvr->key_name);
    new->aaa_server_dh=tr_dh_dup(srvr->aaa_server_dh);
    new->key_expiration=srvr->key_expiration;
    
    tid_srvr_blk_set_path(new, srvr->path);

    tid_srvr_blk_add(new->next, tid_srvr_blk_dup(mem_ctx, srvr->next));
  }
  return new;
}

/* use the macro */
TR_EXPORT TID_SRVR_BLK *tid_srvr_blk_add_func(TID_SRVR_BLK *head, TID_SRVR_BLK *new)
{
  TID_SRVR_BLK *this=head;

  if (head==NULL)
    return new;

  while (this->next!=NULL)
    this=this->next;
  
  this->next=new;
  while (this!=NULL) {
    talloc_steal(head, this);
    this=this->next;
  }
  return head;
}

TR_EXPORT void tid_srvr_blk_set_path(TID_SRVR_BLK *block, TID_PATH *path)
{
  if (block->path!=NULL)
    json_decref((json_t *)(block->path));
  block->path=path;
  if (block->path!=NULL)
    json_incref((json_t *)(block->path));
}

TR_EXPORT const TID_PATH *tid_srvr_get_path( const TID_SRVR_BLK *block)
{
  if (!block)
    return NULL;
  return block->path;
}

TR_EXPORT int tid_srvr_get_key_expiration(const TID_SRVR_BLK *block, struct timeval *tv_out)
{
  if ((block==NULL) || (tv_out==NULL))
    return -1; /* error */

  tv_out->tv_sec=block->key_expiration.tv_sec;
  tv_out->tv_usec=block->key_expiration.tv_usec;
  return 0;
}


TR_EXPORT void tid_resp_set_cons(TID_RESP *resp, TR_CONSTRAINT_SET *cons)
{
  json_t *jc=(json_t *)cons;

  if (resp->cons!=NULL)
    json_decref((json_t *) (resp->cons));

  resp->cons=(TR_CONSTRAINT_SET *)jc;
  if (jc!=NULL)
    json_incref(jc);
}

TR_EXPORT void tid_resp_set_error_path(TID_RESP *resp, json_t *ep)
{
  if (resp->error_path!=NULL)
    json_decref(resp->error_path);
  resp->error_path=ep;
  if (resp->error_path!=NULL)
    json_incref(resp->error_path);
}

TR_EXPORT const TID_PATH *tid_resp_get_error_path(const TID_RESP *resp)
{
  if (!resp)
    return NULL;
  return (const TID_PATH *)(resp->error_path);
}

TR_EXPORT const TID_PATH *tid_resp_get_a_path(const TID_RESP *const_resp)
{
  size_t index;
  TID_SRVR_BLK *server;
  TID_RESP *resp = (TID_RESP *) const_resp;
  if (!resp)
    return NULL;

  if (resp->error_path)
    return (const TID_PATH *)(resp->error_path);
  tid_resp_servers_foreach( resp, server, index) {
    if (server->path)
      return server->path;
  }
  return NULL;
  
}
