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

#include <talloc.h>

#include <trust_router/tr_dh.h>
#include <tr_msg.h>
#include <gsscon.h>
#include <tr_debug.h>
#include <tr_gss_client.h>

TR_GSSC_INSTANCE *tr_gssc_instance_new(TALLOC_CTX *mem_ctx)
{
  TR_GSSC_INSTANCE *gssc=talloc(NULL, TR_GSSC_INSTANCE);
  if (gssc != NULL) {
    gssc->service_name = NULL;
    gssc->conn = -1;
    gssc->gss_ctx = talloc(gssc, gss_ctx_id_t);
    if (gssc->gss_ctx == NULL) {
      talloc_free(gssc);
      return NULL;
    }
  }
  return gssc;
}

void tr_gssc_instance_free(TR_GSSC_INSTANCE *tr_gssc)
{
  talloc_free(tr_gssc);
}

/**
 * Open a connection to the requested server:port
 *
 * @param gssc client instance
 * @param server server name/address
 * @param port TCP port to connect
 * @return 0 on success, -1 on failure
 */
int tr_gssc_open_connection(TR_GSSC_INSTANCE *gssc, const char *server, int port)
{
  if ((port <= 0) || (port > 65535)) {
    tr_err("tr_gssc_open_connection: invalid port requested (%d)", port);
    return -1;
  }

  tr_debug("tr_gssc_open_connection: opening connection to %s:%d", server, port);
  if (0 != gsscon_connect(server, (unsigned int) port, gssc->service_name, &(gssc->conn), gssc->gss_ctx))
    return -1;

  return 0; /* success */
}

/**
 * Send a request message and retrieve a response message
 *
 * @param mem_ctx
 * @param gssc
 * @param req_msg
 * @return decoded message, or null on error
 */
TR_MSG *tr_gssc_exchange_msgs(TALLOC_CTX *mem_ctx, TR_GSSC_INSTANCE *gssc, TR_MSG *req_msg)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  char *req_buf = NULL;
  char *resp_buf = NULL;
  size_t resp_buflen = 0;
  TR_MSG *resp_msg = NULL; /* this is the return value */
  int err;

  /* Validate inputs */
  if ((gssc == NULL) || (req_msg == NULL))
    goto cleanup;

  /* Encode the request into a json string */
  if (!(req_buf = tr_msg_encode(tmp_ctx, req_msg))) {
    tr_err("tr_gssc_exchange_msgs: Error encoding request message.\n");
    goto cleanup;
  }

  tr_debug( "tr_gssc_exchange_msgs: Sending request message:\n%s\n", req_buf);

  /* Send the request over the connection */
  err = gsscon_write_encrypted_token(gssc->conn, *(gssc->gss_ctx), req_buf, strlen(req_buf));
  if (err) {
    tr_err( "tr_gssc_exchange_msgs: Error sending request.\n");
    goto cleanup;
  }

  /* Read the response from the connection */
  /* TBD -- timeout? */
  if (gsscon_read_encrypted_token(gssc->conn, *(gssc->gss_ctx), &resp_buf, &resp_buflen))
    goto cleanup;

  tr_debug( "tr_gssc_exchange_msgs: Response Received (%u bytes).\n%s\n", (unsigned) resp_buflen, resp_buf);
  resp_msg = tr_msg_decode(mem_ctx, resp_buf, resp_buflen);
  free(resp_buf);

  if (resp_msg == NULL) {
    tr_err( "tr_gssc_exchange_msgs: Error decoding response.\n");
    goto cleanup;
  }

  /* If we get here, then we decoded the message and resp_msg is not null. Nothing more to do. */

cleanup:
  talloc_free(tmp_ctx);
  return resp_msg;
}
