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
#include <glib.h>

#include <mon_internal.h>

/* Monitoring request encoders */

/**
 * Encode options array as a JSON array
 *
 * Format:
 * [
 *   { "type": "first_type" },
 *   { "type": "second_type"},
 *   ...
 * ]
 *
 * @param opts array of options
 * @return reference to a JSON array of options
 */
static json_t *mon_opts_encode(GArray *opts)
{
  json_t *array_json = json_array(); // the array of options
  json_t *opt_json = NULL; // individual option JSON object
  json_t *type_json = NULL;
  guint ii = 0;
  MON_OPT this_opt;

  if (array_json == NULL)
    return NULL; // failed

  /* Iterate over the options */
  for (ii=0; ii < opts->len; ii++) {
    this_opt = g_array_index(opts, MON_OPT, ii);

    /* Create the JSON object for this option */
    opt_json = json_object();
    if (opt_json == NULL) {
      json_decref(array_json);
      return NULL;
    }

    /* Add to the array, making opt_json a borrowed ref if we succeed */
    if (json_array_append_new(array_json, opt_json) == -1) {
      json_decref(array_json);
      json_decref(opt_json); // handle ourselves because the set failed
    }

    /* Create the type string for this option */
    type_json = json_string(mon_opt_type_to_string(this_opt.type));
    if (type_json == NULL) {
      json_decref(array_json);
      return NULL;
    }

    /* Add the type string to the JSON object, making type_json a borrowed ref */
    if (json_object_set_new(opt_json, "type", type_json) == -1) {
      json_decref(array_json);
      json_decref(type_json); // must handle ourselves because the set failed
      return NULL;
    }
  }

  return array_json;
}

/**
 * Encode a request as a JSON object
 *
 * Caller must free the return value using json_decref()
 *
 * Format:
 * {
 *   "command": "some_command",
 *   "options": [...see mon_opts_to_json()...]
 * }
 *
 * @param req request to encode
 * @return reference to a JSON object
 */
json_t *mon_req_encode(MON_REQ *req)
{
  json_t *req_json = NULL;
  json_t *cmd_json = NULL;
  json_t *opts_json = NULL;

  /* Allocate the base JSON object */
  req_json = json_object();
  if (req_json == NULL)
    return NULL;

  /* Allocate the JSON string for the command */
  cmd_json = json_string(mon_cmd_to_string(req->command));
  if (cmd_json == NULL) {
    json_decref(req_json);
    return NULL;
  }

  /* Add the command string to the base object. Steals the reference to
   * the string if successful. */
  if (json_object_set_new(req_json, "command", cmd_json) == -1) {
    json_decref(cmd_json); // must clean this up ourselves because the set failed
    json_decref(req_json);
    return NULL;
  }

  /* If we have options, add them to the object */
  if (req->options->len > 0) {
    opts_json = mon_opts_encode(req->options);
    if (opts_json == NULL) {
      json_decref(req_json);
      return NULL;
    }

    if (json_object_set_new(req_json, "options", opts_json) == -1) {
      json_decref(req_json);
      json_decref(opts_json); // must clean this up ourselves because set failed
      return NULL;
    }
  }

  /* That's it, we succeeded */
  return req_json;
}

