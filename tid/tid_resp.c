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
    resp->num_servers=0;
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

TR_EXPORT TID_SRVR_BLK *tid_resp_get_server(TID_RESP *resp,
					    size_t index)
{
  assert(resp);
  assert(index < resp->num_servers);
  return(&(resp->servers[index]));
}

size_t tid_resp_get_num_servers(const TID_RESP *resp)
{
  assert(resp);
  return resp->num_servers;
}


const TID_PATH *tid_srvr_get_path( const TID_SRVR_BLK *block)
{
  if (!block)
    return NULL;
  return (const TID_PATH *) block->path;
}

const TID_PATH *tid_resp_get_error_path( const TID_RESP *resp)
{
  if (!resp)
    return NULL;
  return (const TID_PATH *) resp->error_path;
}

const TID_PATH *tid_resp_get_a_path( const TID_RESP *const_resp)
{
  size_t index;
  TID_SRVR_BLK *server;
  TID_RESP *resp = (TID_RESP *) const_resp;
  if (!resp)
    return NULL;


  if (resp->error_path)
    return (const TID_PATH *) resp->error_path;
  tid_resp_servers_foreach( resp, server, index) {
    if (server->path)
      return (const TID_PATH *) server->path;
  }
  return NULL;
  
}
