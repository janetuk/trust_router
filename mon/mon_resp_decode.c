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
#include <jansson.h>

#include <mon_internal.h>

// Monitoring response decoder

/**
 * Decode a JSON response
 *
 * Expected format:
 * {
 *   "code": 0,
 *   "message": "success",
 *   "payload": {
 *     "serial": 12345,
 *     ...
 *   }
 * }
 *
 * Caller must free the return value with MON_REQ_free().
 *
 * @param mem_ctx talloc context for the returned struct
 * @param resp_json reference to JSON request object
 * @return decoded request struct or NULL on failure
 */
MON_RESP *mon_resp_decode(TALLOC_CTX *mem_ctx, json_t *resp_json)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  MON_RESP *resp = NULL;
  json_t *jcode = NULL;
  json_t *jmessage = NULL;
  json_t *jpayload = NULL;

  if (! json_is_object(resp_json))
    goto cleanup;

  /* Get the response code, which is an integer */
  jcode = json_object_get(resp_json, "code");
  if (! json_is_integer(jcode))
    goto cleanup;

  /* Get the response message, which is a string */
  jmessage = json_object_get(resp_json, "message");
  if (! json_is_string(jmessage))
    goto cleanup;

  /* Get the payload if we have one */
  jpayload = json_object_get(resp_json, "payload");

  /* Get a response in the tmp_ctx context. The payload may be null. */
  resp = mon_resp_new(tmp_ctx,
                      (MON_RESP_CODE) json_integer_value(jcode),
                      json_string_value(jmessage),
                      jpayload);
  if (resp == NULL)
    goto cleanup;

  /* Success! Put the request in the caller's talloc context */
  talloc_steal(mem_ctx, resp);

cleanup:
  talloc_free(tmp_ctx);
  if (resp_json)
    json_decref(resp_json);

  return resp;
}
