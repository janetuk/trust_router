/*
 * Copyright (c) 2018, JANET(UK)
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
#include <tr_name_internal.h>

#include <mon_internal.h>

// Monitoring request message common code

/**
 * Destructor used by talloc to ensure proper cleanup
 */
static int mon_resp_destructor(void *object)
{
  MON_RESP *resp = talloc_get_type_abort(object, MON_RESP);
  /* free the message */
  if (resp->message) {
    tr_free_name(resp->message);
  }
  /* free the payload */
  if (resp->payload) {
    json_decref(resp->payload);
  }
  return 0;
}

/**
 * Allocate a new monitoring response
 *
 * Caller must free using mon_resp_free().
 *
 * Makes its own copy of the message, so caller can dispose of
 * that after allocating the response.
 *
 * Increments the reference count of the payload if it is not null.
 *
 * @param mem_ctx talloc context for allocation
 * @param req MON_REQ this response corresponds to
 * @param code numeric response code
 * @param msg string description of response code
 * @param payload JSON object to be send as payload, or null for no payload
 * @return response allocated in the requested talloc context, null on failure
 */
MON_RESP *mon_resp_new(TALLOC_CTX *mem_ctx, MON_RESP_CODE code, const char *msg, json_t *payload)
{
  MON_RESP *resp = talloc(mem_ctx, MON_RESP);
  if (resp) {
    resp->code = code;
    resp->message = tr_new_name(msg);

    resp->payload = payload;
    if (resp->payload)
      json_incref(resp->payload);

    talloc_set_destructor((void *)resp, mon_resp_destructor);
    if (resp->message == NULL) {
      talloc_free(resp); // destructor will be called
      resp = NULL;
    }
  }
  return resp;
}

/**
 * Free a monitoring response
 *
 * @param resp request to free, must not be null
 */
void mon_resp_free(MON_RESP *resp)
{
  talloc_free(resp);
}
