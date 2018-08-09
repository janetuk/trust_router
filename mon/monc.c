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


MONC_INSTANCE *monc_new(TALLOC_CTX *mem_ctx)
{
  MONC_INSTANCE *monc=talloc(mem_ctx, MONC_INSTANCE);
  if (monc!=NULL) {
    monc->gssc = tr_gssc_instance_new(monc);
    if (monc->gssc == NULL) {
      talloc_free(monc);
      return NULL;
    }

    monc->gssc->service_name = "trustmonitor";

    mon_tr_msg_init(); /* Prepare to send messages */
  }
  return monc;
}

void monc_free(MONC_INSTANCE *monc)
{
  talloc_free(monc);
}

int monc_open_connection(MONC_INSTANCE *monc,
                         const char *server,
                         int port)
{
  return tr_gssc_open_connection(monc->gssc, server, port);
}

MON_RESP *monc_send_request(TALLOC_CTX *mem_ctx, MONC_INSTANCE *monc, MON_REQ *req)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  TR_MSG *msg = NULL;
  TR_MSG *resp_msg = NULL;
  MON_RESP *resp = NULL;

  /* Create and populate a msg structure */
  if (!(msg = talloc_zero(tmp_ctx, TR_MSG)))
    goto cleanup;

  tr_msg_set_mon_req(msg, req);

  resp_msg = tr_gssc_exchange_msgs(tmp_ctx, monc->gssc, msg);
  if (resp_msg == NULL)
    goto cleanup;

  resp = tr_msg_get_mon_resp(resp_msg);

  /* if we got a response, steal it from resp_msg's context so we can return it */
  if (resp)
    talloc_steal(mem_ctx, resp);

cleanup:
  talloc_free(tmp_ctx);
  return resp;
}
