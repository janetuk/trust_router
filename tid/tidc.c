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
#include <jansson.h>

#include <trust_router/tr_dh.h>
#include <tid_internal.h>
#include <tr_msg.h>
#include <gsscon.h>

int tmp_len = 32;

TIDC_INSTANCE *tidc_create ()
{
  TIDC_INSTANCE *tidc = NULL;

  if (tidc = malloc(sizeof(TIDC_INSTANCE))) 
    memset(tidc, 0, sizeof(TIDC_INSTANCE));
  else
    return NULL;

  return tidc;
}

void tidc_destroy (TIDC_INSTANCE *tidc)
{
  if (tidc)
    free(tidc);
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

  fprintf(stderr, "tidc_open_connection: Opening GSS connection to %s:%u.", server, use_port);  
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

  /* Create and populate a TID req structure */
  if (!(tid_req = malloc(sizeof(TID_REQ))))
    return -1;

  memset(tid_req, 0, sizeof(TID_REQ));

  tid_req->conn = conn;
  tid_req->gssctx = gssctx;

  if ((NULL == (tid_req->rp_realm = tr_new_name(rp_realm))) ||
      (NULL == (tid_req->realm = tr_new_name(realm))) ||
      (NULL == (tid_req->comm = tr_new_name(comm)))) {
    fprintf (stderr, "tidc_send_request: Error duplicating names.\n");
    return -1;
  }

  tid_req->tidc_dh = tidc->client_dh;

  return (tidc_fwd_request(tidc, tid_req, resp_handler, cookie));
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

  /* Create and populate a TID msg structure */
  if (!(msg = malloc(sizeof(TR_MSG))))
    return -1;

  msg->msg_type = TID_REQUEST;
  msg->tid_req = tid_req;

  /* store the response function and cookie */
  // tid_req->resp_func = resp_handler;
  // tid_req->cookie = cookie;
  

  /* Encode the request into a json string */
  if (!(req_buf = tr_msg_encode(msg))) {
    fprintf(stderr, "tidc_fwd_request: Error encoding TID request.\n");
    return -1;
  }

  fprintf (stderr, "tidc_fwd_request: Sending TID request:\n");
  fprintf (stderr, "%s\n", req_buf);

  /* Send the request over the connection */
  if (err = gsscon_write_encrypted_token (tid_req->conn, tid_req->gssctx, req_buf, 
					  strlen(req_buf))) {
    fprintf(stderr, "tidc_fwd_request: Error sending request over connection.\n");
    return -1;
  }

  /* TBD -- queue request on instance, read resps in separate thread */

  /* Read the response from the connection */
  /* TBD -- timeout? */
  if (err = gsscon_read_encrypted_token(tid_req->conn, tid_req->gssctx, &resp_buf, &resp_buflen)) {
    if (resp_buf)
      free(resp_buf);
    return -1;
  }

  fprintf(stdout, "tidc_fwd_request: Response Received (%u bytes).\n", (unsigned) resp_buflen);
  fprintf(stdout, "%s\n", resp_buf);

  if (NULL == (resp_msg = tr_msg_decode(resp_buf, resp_buflen))) {
    fprintf(stderr, "tidc_fwd_request: Error decoding response.\n");
    return -1;
  }

  /* TBD -- Check if this is actually a valid response */
  if (!resp_msg->tid_resp) {
    fprintf(stderr, "tidc_fwd_request: Error, no response in the response!\n");
    return -1;
  }
  
  if (resp_handler)
    /* Call the caller's response function */
    (*resp_handler)(tidc, tid_req, resp_msg->tid_resp, cookie);
  else
    fprintf(stderr, "tidc_fwd_request: NULL response function.\n");

  if (msg)
    free(msg);
  if (tid_req)
    tid_req_free(tid_req);
  if (req_buf)
    free(req_buf);
  if (resp_buf)
    free(resp_buf);

  /* TBD -- free the decoded response */

  return 0;
}

