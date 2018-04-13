/*
 * Copyright (c) 2012, 2014-2018, JANET(UK)
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
#include <mon_internal.h>
#include <tr_msg.h>
#include <gsscon.h>
#include <tr_debug.h>


static int monc_destructor(void *obj)
{
  MONC_INSTANCE *monc=talloc_get_type_abort(obj, MONC_INSTANCE);
  if (NULL!=monc) {
    if (NULL!=monc->client_dh)
      tr_destroy_dh_params(monc->client_dh);
  }
  return 0;
}

/* creates struct in talloc null context */
MONC_INSTANCE *monc_create(void)
{
  MONC_INSTANCE *monc=talloc(NULL, MONC_INSTANCE);
  if (monc!=NULL) {
    monc->client_dh=NULL;
    talloc_set_destructor((void *)monc, monc_destructor);
  }
  return monc;
}

void monc_destroy(MONC_INSTANCE *monc)
{
  talloc_free(monc);
}

int monc_open_connection (MONC_INSTANCE *monc,
                          const char *server,
                          unsigned int port,
                          gss_ctx_id_t *gssctx)
{
  int err = 0;
  int conn = -1;

  tr_debug("monc_open_connection: opening monc connection to %s:%d", server, port);
  err = gsscon_connect(server, port, "trustmonitor", &conn, gssctx);

  if (!err)
    return conn;
  else
    return -1;
}

int monc_send_request (MONC_INSTANCE *monc,
                       int conn,
                       gss_ctx_id_t gssctx,
                       MONC_RESP_FUNC *resp_handler,
                       void *cookie)
{
  MON_REQ *mon_req = NULL;
  int rc;

  /* Create and populate a MON req structure */
  if (!(mon_req = mon_req_new(NULL, MON_CMD_SHOW))) // TODO accept command as a parameter
    goto error;

  rc = monc_fwd_request(monc, conn, gssctx, mon_req, resp_handler, cookie);
  goto cleanup;
error:
  rc = -1;
cleanup:
  mon_req_free(mon_req);
  return rc;
}

int monc_fwd_request(MONC_INSTANCE *monc,
                     int conn,
                     gss_ctx_id_t gssctx,
                     MON_REQ *mon_req,
                     MONC_RESP_FUNC *resp_handler,
                     void *cookie)
{
  char *req_buf = NULL;
  char *resp_buf = NULL;
  size_t resp_buflen = 0;
  TR_MSG *msg = NULL;
  TR_MSG *resp_msg = NULL;
  int err;
  int rc = 0;

  /* Create and populate a MON msg structure */
  if (!(msg = talloc_zero(mon_req, TR_MSG)))
    goto error;

  msg->msg_type = MON_REQUEST;
  tr_msg_set_mon_req(msg, mon_req);

  /* store the response function and cookie */
  // mon_req->resp_func = resp_handler;
  // mon_req->cookie = cookie;


  /* Encode the request into a json string */
  if (!(req_buf = tr_msg_encode(NULL, msg))) {
    tr_err("monc_fwd_request: Error encoding MON request.\n");
    goto error;
  }

  tr_debug( "monc_fwd_request: Sending MON request:\n");
  tr_debug( "%s\n", req_buf);

  /* Send the request over the connection */
  err = gsscon_write_encrypted_token (conn, gssctx, req_buf, strlen(req_buf));
  if (err) {
    tr_err( "monc_fwd_request: Error sending request over connection.\n");
    goto error;
  }

  /* TBD -- queue request on instance, read resps in separate thread */

  /* Read the response from the connection */
  /* TBD -- timeout? */
  if (err = gsscon_read_encrypted_token(conn, gssctx, &resp_buf, &resp_buflen)) {
    if (resp_buf)
      free(resp_buf);
    goto error;
  }

  tr_debug( "monc_fwd_request: Response Received (%u bytes).\n", (unsigned) resp_buflen);
  tr_debug( "%s\n", resp_buf);

//  if (NULL == (resp_msg = tr_msg_decode(resp_buf, resp_buflen))) {
//    tr_err( "monc_fwd_request: Error decoding response.\n");
//    goto error;
//  }
//
//  /* TBD -- Check if this is actually a valid response */
//  if (MON_RESPONSE != tr_msg_get_msg_type(resp_msg)) {
//    tr_err( "monc_fwd_request: Error, no response in the response!\n");
//    goto error;
//  }
//
//  if (resp_handler) {
//    /* Call the caller's response function. It must copy any data it needs before returning. */
//    tr_debug("monc_fwd_request: calling response callback function.");
//    (*resp_handler)(monc, mon_req, tr_msg_get_resp(resp_msg), cookie);
//  }

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
  if (resp_msg)
    tr_msg_free_decoded(resp_msg);
  return rc;
}


DH * monc_get_dh(MONC_INSTANCE *inst)
{
  return inst->client_dh;
}

DH *monc_set_dh(MONC_INSTANCE *inst, DH *dh)
{
  inst->client_dh = dh;
  return dh;
}
