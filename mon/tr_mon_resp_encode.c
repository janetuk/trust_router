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

#include <tr_mon.h>

/* Helper for encoding. Adds a newly allocated JSON object to
 * jobj. If the allocation or setting fails, returns NULL after
 * cleaning up. */
#define object_set_or_free_and_return(jobj, tmp_jval, key, jval)  \
  do {                                                            \
    (tmp_jval) = (jval);                                          \
    if ( (tmp_jval) == NULL) {                                    \
      json_decref(jobj);                                          \
      return NULL;                                                \
    }                                                             \
    if (json_object_set_new((jobj), (key), (tmp_jval)) == -1) {   \
      json_decref(tmp_jval);                                      \
      json_decref(jobj);                                          \
      return NULL;                                                \
    }                                                             \
  } while(0)

/**
 * Encode a monitoring response as a JSON object
 *
 * Caller must ensure json_decref() is used to free the return value.
 *
 * @param resp response to encode
 * @return response as a newly allocated JSON object
 */
json_t *tr_mon_resp_encode(TR_MON_RESP *resp)
{
  json_t *resp_json = NULL;
  json_t *jval = NULL;
  const char *cmd_str = NULL;

  /* Get a JSON object */
  resp_json = json_object();
  if (resp_json == NULL)
    return NULL;

  /* Add properties, cleaning up and returning NULL on failure */
  object_set_or_free_and_return(resp_json, jval, "code",    json_integer(resp->code));
  object_set_or_free_and_return(resp_json, jval, "message", tr_name_to_json_string(resp->message));

  /* If we have a payload, add it */
  if (resp->payload) {
    cmd_str = cmd_to_string(resp->req->command); // key for the response payload
    object_set_or_free_and_return(resp_json, jval, cmd_str, resp->payload);
  }

  return resp_json;
}
