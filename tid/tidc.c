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
#include <jansson.h>
#include <talloc.h>

#include <trust_router/tr_dh.h>
#include <tid_internal.h>
#include <tr_msg.h>
#include <gsscon.h>
#include <tr_debug.h>


int tmp_len = 32;

TIDC_INSTANCE *tidc_create ()
{
  TIDC_INSTANCE *tidc = NULL;

  if (NULL == (tidc = talloc_zero(NULL, TIDC_INSTANCE)))
    return NULL;

  return tidc;
}

void tidc_destroy (TIDC_INSTANCE *tidc)
{
  talloc_free(tidc);
}

int tidc_open_connection (TIDC_INSTANCE *tidc, 
			  char *server,
			  unsigned int port,
			  gss_ctx_id_t *gssctx)
{
  int err = 0;
  int conn = -1;
  unsigned int use_port = 0;

  if (0 == port)
    use_port = TID_PORT;
  else
    use_port = port;

  err = gsscon_connect(server, use_port, "trustidentity", &conn, gssctx);

  if (!err)
    return conn;
  else
    return -1;
}

int tidc_send_request (TIDC_INSTANCE *tidc,
		       int conn,
		       gss_ctx_id_t gssctx,
		       char *rp_realm,
		       char *realm, 
		       char *comm,
		       TIDC_RESP_FUNC *resp_handler,
		       void *cookie)
{
  TID_REQ *tid_req = NULL;
  int rc;

  /* Create and populate a TID req structure */
  if (!(tid_req = tid_req_new()))
    return -1;

  tid_req->conn = conn;
  tid_req->gssctx = gssctx;

  if ((NULL == (tid_req->rp_realm = tr_new_name(rp_realm))) ||
      (NULL == (tid_req->realm = tr_new_name(realm))) ||
      (NULL == (tid_req->comm = tr_new_name(comm)))) {
    tr_err ( "tidc_send_request: Error duplicating names.\n");
    goto error;
  }

  tid_req->tidc_dh = tidc->client_dh;

  rc = tidc_fwd_request(tidc, tid_req, resp_handler, cookie);
  goto cleanup;
 error:
  rc = -1;
 cleanup:
  tid_req_free(tid_req);
  return rc;
}

int tidc_fwd_request (TIDC_INSTANCE *tidc,
		      TID_REQ *tid_req,
		      TIDC_RESP_FUNC *resp_handler,
		      void *cookie)
{
  char *req_buf = NULL;
  char *resp_buf = NULL;
  size_t resp_buflen = 0;
  TR_MSG *msg = NULL;
  TR_MSG *resp_msg = NULL;
  int err;
  int rc = 0;

  /* Create and populate a TID msg structure */
  if (!(msg = talloc_zero(tid_req, TR_MSG)))
    goto error;

  msg->msg_type = TID_REQUEST;
  tr_msg_set_req(msg, tid_req);

  /* store the response function and cookie */
  // tid_req->resp_func = resp_handler;
  // tid_req->cookie = cookie;


  /* Encode the request into a json string */
  if (!(req_buf = tr_msg_encode(msg))) {
    tr_err("tidc_fwd_request: Error encoding TID request.\n");
    goto error;
  }

  tr_debug( "tidc_fwd_request: Sending TID request:\n");
  tr_debug( "%s\n", req_buf);

  /* Send the request over the connection */
  if (err = gsscon_write_encrypted_token (tid_req->conn, tid_req->gssctx, req_buf,
					  strlen(req_buf))) {
    tr_err( "tidc_fwd_request: Error sending request over connection.\n");
    goto error;
  }

  /* TBD -- queue request on instance, read resps in separate thread */

  /* Read the response from the connection */
  /* TBD -- timeout? */
  if (err = gsscon_read_encrypted_token(tid_req->conn, tid_req->gssctx, &resp_buf, &resp_buflen)) {
    if (resp_buf)
      free(resp_buf);
    goto error;
  }

  tr_debug( "tidc_fwd_request: Response Received (%u bytes).\n", (unsigned) resp_buflen);
  tr_debug( "%s\n", resp_buf);

  if (NULL == (resp_msg = tr_msg_decode(resp_buf, resp_buflen))) {
    tr_err( "tidc_fwd_request: Error decoding response.\n");
    goto error;
  }

  /* TBD -- Check if this is actually a valid response */
  if (TID_RESPONSE != tr_msg_get_msg_type(resp_msg)) {
    tr_err( "tidc_fwd_request: Error, no response in the response!\n");
    goto error;
  }

  if (resp_handler)
    /* Call the caller's response function */
    (*resp_handler)(tidc, tid_req, tr_msg_get_resp(resp_msg), cookie);
  goto cleanup;

 error:
  rc = -1;
 cleanup:
  if (msg)
    talloc_free(msg);
  if (req_buf)
    free(req_buf);
  if (resp_buf)
    free(resp_buf);

  /* TBD -- free the decoded response */

  return rc;
}


DH * tidc_get_dh(TIDC_INSTANCE *inst)
{
  return inst->client_dh;
}

DH *tidc_set_dh(TIDC_INSTANCE *inst, DH *dh)
{
  inst->client_dh = dh;
  return dh;
}
