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

#include <gsscon.h>
#include <trust_router/tr_dh.h>
#include <tid_internal.h>
#include <tr_msg.h>
#include <tr_debug.h>


int tmp_len = 32;

/* creates struct in talloc null context */
TIDC_INSTANCE *tidc_create(void)
{
  TIDC_INSTANCE *tidc=talloc(NULL, TIDC_INSTANCE);
  if (tidc!=NULL) {
    tidc->gssc = tr_gssc_instance_new(tidc);
    if (tidc->gssc == NULL) {
      talloc_free(tidc);
      return NULL;
    }

    tidc->gssc->service_name = "trustidentity";
  }
  return tidc;
}

void tidc_destroy(TIDC_INSTANCE *tidc)
{
  talloc_free(tidc);
}

int tidc_open_connection (TIDC_INSTANCE *tidc, 
                          const char *server,
                          unsigned int port,
                          gss_ctx_id_t *gssctx)
{
  unsigned int use_port = 0;
  tidc->gssc->gss_ctx = gssctx;

  if (0 == port)
    use_port = TID_PORT;
  else
    use_port = port;

  tr_debug("tidc_open_connection: opening tidc connection to %s:%d", server, use_port);
  if (0 == tr_gssc_open_connection(tidc->gssc, server, use_port))
    return tidc->gssc->conn;
  else
    return -1;
}

int tidc_send_request (TIDC_INSTANCE *tidc,
                       int conn,
                       gss_ctx_id_t gssctx,
                       const char *rp_realm,
                       const char *realm,
                       const char *comm,
                       TIDC_RESP_FUNC *resp_handler,
                       void *cookie)
{
  TID_REQ *tid_req = NULL;
  int rc;
  int orig_conn = 0;
  gss_ctx_id_t *orig_gss_ctx = NULL;

  /* For ABI compatibility, replace the generic GSS client parameters
   * with the arguments we were passed. */
  orig_conn = tidc->gssc->conn; /* save to restore later */
  if (conn != tidc->gssc->conn) {
    tr_warning("tidc_send_request: WARNING: socket connection FD does not match FD opened by tidc_open_connection()");
    tidc->gssc->conn = conn;
  }
  orig_gss_ctx = tidc->gssc->gss_ctx; /* save to restore later */
  if (gssctx != *(tidc->gssc->gss_ctx)) {
    tr_warning("tidc_send_request: WARNING: sending request with different GSS context than used for tidc_open_connection()");
    *tidc->gssc->gss_ctx = gssctx;
  }

  /* Create and populate a TID req structure */
  if (!(tid_req = tid_req_new()))
    goto error;

  tid_req->conn = conn;
  tid_req->gssctx = gssctx;

  if ((NULL == (tid_req->rp_realm = tr_new_name(rp_realm))) ||
      (NULL == (tid_req->realm = tr_new_name(realm))) ||
      (NULL == (tid_req->comm = tr_new_name(comm)))) {
    tr_err ( "tidc_send_request: Error duplicating names.\n");
    goto error;
  }

  tid_req->tidc_dh = tr_dh_dup(tidc->gssc->client_dh);

  rc = tidc_fwd_request(tidc, tid_req, resp_handler, cookie);
  goto cleanup;
 error:
  rc = -1;
 cleanup:
  if (tid_req)
    tid_req_free(tid_req);

  tidc->gssc->conn = orig_conn;
  tidc->gssc->gss_ctx = orig_gss_ctx;
  return rc;
}

int tidc_fwd_request(TIDC_INSTANCE *tidc,
                     TID_REQ *tid_req,
                     TIDC_RESP_FUNC *resp_handler,
                     void *cookie)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  TR_MSG *msg = NULL;
  TR_MSG *resp_msg = NULL;
  int rc = 0;

  /* Create and populate a TID msg structure */
  if (!(msg = talloc_zero(tmp_ctx, TR_MSG)))
    goto error;

  msg->msg_type = TID_REQUEST;
  tr_msg_set_req(msg, tid_req);


  tr_debug( "tidc_fwd_request: Sending TID request\n");

  /* Send the request over the connection */
  resp_msg = tr_gssc_exchange_msgs(tmp_ctx, tidc->gssc, msg);
  if (resp_msg == NULL)
    goto error;

  /* TBD -- Check if this is actually a valid response */
  if (TID_RESPONSE != tr_msg_get_msg_type(resp_msg)) {
    tr_err( "tidc_fwd_request: Error, no response in the response!\n");
    goto error;
  }

  if (resp_handler) {
    /* Call the caller's response function. It must copy any data it needs before returning. */
    tr_debug("tidc_fwd_request: calling response callback function.");
    (*resp_handler)(tidc, tid_req, tr_msg_get_resp(resp_msg), cookie);
  }

  goto cleanup;

 error:
  rc = -1;
 cleanup:
  talloc_free(tmp_ctx);
  return rc;
}


DH * tidc_get_dh(TIDC_INSTANCE *inst)
{
  return tr_gssc_get_dh(inst->gssc);
}

DH *tidc_set_dh(TIDC_INSTANCE *inst, DH *dh)
{
  return tr_gssc_set_dh(inst->gssc, dh);
}
