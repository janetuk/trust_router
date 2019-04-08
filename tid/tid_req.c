/*
 * Copyright (c) 2012, 2014-2015, JANET(UK)
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
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <talloc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <tid_internal.h>
#include <tr_debug.h>

#include <jansson.h>

static int destroy_tid_req(TID_REQ *req)
{
  if (req->json_references)
    json_decref(req->json_references);
  if (req->free_conn) {
    if (req->conn)
      close(req->conn);
    if (req->gssctx) {
      OM_uint32 minor;
      gss_delete_sec_context( &minor, &req->gssctx, NULL);
    }
  }
  if (req->rp_realm!=NULL)
    tr_free_name(req->rp_realm);
  if (req->realm!=NULL)
    tr_free_name(req->realm);
  if (req->comm!=NULL)
    tr_free_name(req->comm);
  if (req->orig_coi!=NULL)
    tr_free_name(req->orig_coi);
  if (req->request_id!=NULL)
    tr_free_name(req->request_id);
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
  req->free_conn = 1;
  req->request_id = NULL;
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

void tid_req_set_orig_coi(TID_REQ *req, TR_NAME *orig_coi)
{
  req->orig_coi = orig_coi;
}

void tid_req_set_request_id(TID_REQ *req, TR_NAME *request_id)
{
  req->request_id = request_id;
}

TR_NAME *tid_req_get_request_id(TID_REQ *req)
{
  return(req->request_id);
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

/* struct is allocated in talloc null context */
TID_REQ *tid_dup_req (TID_REQ *orig_req) 
{
  TID_REQ *new_req = NULL;

  if (NULL == (new_req = talloc_zero(NULL, TID_REQ))) {
    tr_crit("tid_dup_req: Can't allocated duplicate request.");
    return NULL;
  }

  /* Memcpy for flat fields, not valid until names are duped. */
  memcpy(new_req, orig_req, sizeof(TID_REQ));
  json_incref(new_req->json_references);
  new_req->free_conn = 0;
  
  if ((NULL == (new_req->rp_realm = tr_dup_name(orig_req->rp_realm))) ||
      (NULL == (new_req->realm = tr_dup_name(orig_req->realm))) ||
      (NULL == (new_req->comm = tr_dup_name(orig_req->comm)))) {
	tr_crit("tid_dup_req: Can't duplicate request (names).");
  }

  if (orig_req->orig_coi) {
    if (NULL == (new_req->orig_coi = tr_dup_name(orig_req->orig_coi))) {
      tr_crit("tid_dup_req: Can't duplicate request (orig_coi).");
    }
  }

  if (orig_req->request_id) {
    if (NULL == (new_req->request_id = tr_dup_name(orig_req->request_id))) {
      tr_crit("tid_dup_req: Can't duplicate request (request_id).");
    }
  }

  return new_req;
}


/* Adds the JSON object ref to req's list of objects to release when the
 * req is freed.
 */
void tid_req_cleanup_json( TID_REQ *req, json_t *ref)
{
  (void) json_array_append_new(req->json_references, ref);
}

void tid_req_free(TID_REQ *req)
{
  talloc_free(req);
}

int tid_req_add_path(TID_REQ *req,
                     const char *this_system, int port)
{
  char *path_element = talloc_asprintf(req, "%s:%u",
				       this_system, port);
  if (!req->path) {
    req->path = json_array();
    if (!req->path)
      return -1;
    tid_req_cleanup_json(req, req->path);
  }
  return json_array_append( req->path, json_string(path_element));
}



void tid_srvr_get_address(const TID_SRVR_BLK *blk,
			  const struct sockaddr **out_addr,
			  size_t *out_len)
{
    char *colon = NULL;
    assert(blk);
    char *hostname = NULL, *port = NULL;
    int s, len;
    struct addrinfo *result;

    // make sure we don't return garbage
    *out_len = 0;
    *out_addr = NULL;

    /* get a copy of the address */
    hostname = talloc_strdup(blk, blk->aaa_server_addr);

    /* address might contain AAA port number. If so, process it */
    colon = strrchr(hostname, ':');

    /* If there are more than one colon, and the last one is not preceeded by ],
       this is not a port separator, but an IPv6 address (likely) */
    if (strchr(hostname, ':') != colon && *(colon - 1) != ']')
      colon = NULL;

    /* we get two strings, the hostname without the colon, and the port number */
    if (colon != NULL) {
      *colon = '\0';
      port = talloc_strdup(blk, colon + 1);
    }

    /* IPv6 addresses might be surrounded by square brackets */
    len = strlen(hostname);
    if (hostname[0] == '[' && hostname[len - 1] == ']') {
        char *copy = talloc_strndup(NULL, hostname + 1, len - 2);
        talloc_free(hostname);
        hostname = copy;
    }

    s = getaddrinfo(hostname,             // address
                    port ? port : "2083", // port as a string
                    NULL,                 // hints
                    &result);
    if (s != 0 || result == NULL) {
      tr_crit("tid_srvr_get_address: Could not resolve an address from %s", hostname);
      return;
    }

    *out_addr = result->ai_addr;
    *out_len = result->ai_addrlen;

    result->ai_addr = NULL; // to avoid deleting it
    freeaddrinfo(result);
    talloc_free(hostname);
    talloc_free(port);
}

DH *tid_srvr_get_dh( TID_SRVR_BLK *blk)
{
  assert(blk);
  return blk->aaa_server_dh;
}

const TR_NAME *tid_srvr_get_key_name(
				    const TID_SRVR_BLK *blk)
{
  assert(blk);
  return blk->key_name;
}
