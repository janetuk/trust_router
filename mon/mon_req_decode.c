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

// Monitoring request decoders

/**
 * Decode a single option
 *
 * Format:
 * { "type": "some_tpye" }
 *
 * @param opt_json JSON object reference
 * @param dest allocated memory for the result
 * @return MON_SUCCESS on success, error on error
 */
static MON_RC mon_decode_one_opt(json_t *opt_json, MON_OPT *dest)
{
  json_t *jstr = NULL;
  MON_OPT_TYPE opt_type = OPT_TYPE_UNKNOWN;

  if ( (opt_json == NULL) || (dest == NULL))
    return MON_BADARG;

  if (! json_is_object(opt_json))
    return MON_NOPARSE;

  jstr = json_object_get(opt_json, "type");
  if ( (jstr == NULL) || (! json_is_string(jstr)) )
    return MON_NOPARSE;

  opt_type = mon_opt_type_from_string(json_string_value(jstr));
  if (opt_type == OPT_TYPE_UNKNOWN)
    return MON_NOPARSE;

  dest->type = opt_type;
  return MON_SUCCESS;
}

/**
 * Decode options array
 *
 * Format:
 * [{option}, {option}, ...]
 *
 */
static MON_RC mon_options_decode(json_t *opts_json, MON_REQ *req)
{
  MON_OPT opt; // not a pointer
  size_t n_opts=0;
  size_t ii=0;

  if ( (opts_json == NULL) || (req == NULL))
    return MON_BADARG;

  if (! json_is_array(opts_json))
    return MON_NOPARSE;

  n_opts = json_array_size(opts_json);
  for (ii=0; ii < n_opts; ii++) {
    if (mon_decode_one_opt(json_array_get(opts_json, ii),
                           &opt) != MON_SUCCESS) {
      return MON_NOPARSE;
    }
    mon_req_add_option(req, opt.type);
  }
  return MON_SUCCESS;
}

/**
 * Parse JSON for a request
 */
static json_t *mon_req_parse(const char *input)
{
  json_t *parsed_json = NULL;
  json_error_t json_error;

  parsed_json = json_loads(input, JSON_REJECT_DUPLICATES, &json_error);
  return parsed_json;
}

/**
 * Decode a JSON request
 *
 * Expected format:
 * {
 *   "command": "some_command_name",
 *   "options": [{option1}, ...]
 * }
 *
 * (options are optional)
 *
 * Caller must free the return value with MON_REQ_free().
 *
 * @param mem_ctx talloc context for the returned struct
 * @param req_json reference to JSON request object
 * @return decoded request struct or NULL on failure
 */
MON_REQ *mon_req_decode(TALLOC_CTX *mem_ctx, const char *req_str)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  MON_REQ *req = NULL;
  json_t *req_json = NULL;
  json_t *jval = NULL;
  json_t *opts_json = NULL;
  MON_CMD cmd = MON_CMD_UNKNOWN;

  req_json = mon_req_parse(req_str); // TODO: Check errors

  if (! json_is_object(req_json))
    goto cleanup;

  // Get the command and verify that it is a string value
  jval = json_object_get(req_json, "command");
  if (! json_is_string(jval))
    goto cleanup;

  cmd = mon_cmd_from_string(json_string_value(jval));
  if (cmd == MON_CMD_UNKNOWN)
    goto cleanup;

  /* Command is good. Allocate the request in the tmp context */
  req = mon_req_new(tmp_ctx, cmd);
  if (req == NULL)
    goto cleanup;

  /* Parse options if we have any */
  opts_json = json_object_get(req_json, "options");
  if (opts_json) {
    if (mon_options_decode(opts_json, req) != MON_SUCCESS) {
      req = NULL; // memory still in tmp_ctx, so it will be cleaned up
      goto cleanup;
    }
  }

  /* Success! Put the request in the caller's talloc context */
  talloc_steal(mem_ctx, req);

cleanup:
  talloc_free(tmp_ctx);
  if (req_json)
    json_decref(req_json);

  return req;
}
