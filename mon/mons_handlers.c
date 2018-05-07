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

/* Handlers for monitoring requests */

#include <glib.h>

#include <tr_debug.h>
#include <mon_internal.h>
#include <mons_handlers.h>


/* Static Prototypes */
static int dispatch_entry_matches(MONS_DISPATCH_TABLE_ENTRY *e, MON_CMD command, MON_OPT_TYPE opt_type);
static MONS_HANDLER_FUNC *mons_find_handler(MONS_INSTANCE *mons, MON_CMD cmd, MON_OPT_TYPE opt_type);
static void request_helper(void *element, void *data);

struct request_helper_data {
  MON_CMD command;
  MON_OPT_TYPE opt_type;
  json_t *payload; /* json object to add responses to */
  GArray *results;
};

struct handler_result {
  MON_OPT_TYPE opt_type; /* what opt type set this? */
  MON_RC rc;             /* what was its result code? */
  json_t *json_data;        /* what data, if any, is it returning? */
};

/**
 * Call the appropriate handler for a request
 *
 * TODO: report errors from handlers
 *
 * @return a MON_RESP structure or null if there was a processing error
 */
MON_RESP *mons_handle_request(TALLOC_CTX *mem_ctx, MONS_INSTANCE *mons, MON_REQ *req)
{
  MON_RESP *resp = NULL;
  json_t *payload = NULL;
  struct request_helper_data cookie = {0};
  size_t ii = 0;

  tr_debug("mons_handle_request: Handling a request");

  /* Start off by allocating our response with a generic error message */
  resp = mon_resp_new(mem_ctx,
                      MON_RESP_ERROR,
                      "error processing request",
                      NULL);
  if (resp == NULL) {
    /* we can't respond, just return */
    tr_crit("mons_handle_request: Error allocating response structure.");
    goto cleanup;
  }

  /* Now get a JSON object for our return payload */
  payload = json_object();
  if (payload == NULL) {
    tr_crit("mons_handle_request: Error allocating response payload.");
    goto cleanup; /* This will return the generic error message set earlier */
  }

  /* Now call handlers */
  cookie.command = req->command;
  cookie.results = g_array_new(FALSE, TRUE, sizeof(struct handler_result));

  if (mon_req_opt_count(req) == 0) {
    /* call every handler that matches the command */
    cookie.opt_type = OPT_TYPE_ANY;
    g_ptr_array_foreach(mons->handlers, request_helper, &cookie);
  } else {
    /* call only those handlers that match an option */
    for (ii=0; ii < mon_req_opt_count(req); ii++) {
      cookie.opt_type = mon_req_opt_index(req, ii)->type;
      /* Loop over all handlers - we know we can only have one match for each opt type */
      g_ptr_array_foreach(mons->handlers, request_helper, &cookie);
    }
  }

  /* We now have an array of results in cookie.results. If any of these failed, return an error. */
  tr_debug("mons_handle_request: Examining %d handler results", cookie.results->len);
  resp->code = MON_RESP_SUCCESS; /* tentatively set this to success */
  for (ii=0; ii < cookie.results->len; ii++) {
    struct handler_result *this = &g_array_index(cookie.results, struct handler_result, ii);
    if (this->rc != MON_SUCCESS) {
      tr_debug("mons_handle_request: Result %d was an error.", ii);
      resp->code = MON_RESP_ERROR;
    }

    /* add the JSON response even if there was an error */
    if (this->json_data) {
      tr_debug("mons_handle_request: Result %d returned JSON data.", ii);
      json_object_set_new(payload, mon_opt_type_to_string(this->opt_type), this->json_data);
    }
  }

  if (resp->code == MON_RESP_SUCCESS) {
    if (mon_resp_set_message(resp, "success") == 0) {
      /* Failed to set the response message to success - fail ironically, don't send
       * an inconsistent response. */
      tr_crit("mons_handle_request: Error setting response message to 'success'.");
      goto cleanup;
    }
  } else {
    /* Failed - send a response indicating that the overall command succeeded */
    if (mon_resp_set_message(resp, "request processed but an error occurred") == 0) {
      tr_crit("mons_handle_request: Error setting response message after a handler error.");
      goto cleanup;
    }
  }

  /* Attach the accumulated payload to the response */
  if (json_object_size(payload) > 0) {
    tr_debug("mons_handle_request: Attaching payload to response.");
    mon_resp_set_payload(resp, payload);
  }

  tr_debug("mons_handle_request: Successfully processed request.");

cleanup:
  if (payload)
    json_decref(payload);
  if (cookie.results)
    g_array_free(cookie.results, TRUE);
  return resp;
}

/**
 * Register a handler for a command/option combination
 *
 * @param mons
 * @param cmd
 * @param opt_type
 * @param f
 * @param cookie
 * @return
 */
MON_RC mons_register_handler(MONS_INSTANCE *mons,
                             MON_CMD cmd,
                             MON_OPT_TYPE opt_type,
                             MONS_HANDLER_FUNC *f,
                             void *cookie)
{
  MONS_DISPATCH_TABLE_ENTRY *entry = NULL;

  if (mons_find_handler(mons, cmd, opt_type) != NULL) {
    return MON_ERROR;
  }

  /* Put these in the mons talloc context so we don't have to muck about with
   * a free function for the GPtrArray */
  entry = talloc(mons, MONS_DISPATCH_TABLE_ENTRY);
  if (entry == NULL) {
    return MON_NOMEM;
  }
  entry->command = cmd;
  entry->opt_type = opt_type;
  entry->handler = f;
  entry->cookie = cookie;

  g_ptr_array_add(mons->handlers, entry);
  return MON_SUCCESS;
}

/**
 * Two table entries match if none of the commands or opt_types are unknown,
 * if the commands match, and if the opt types either match or at least one is
 * OPT_TYPE_ANY.
 *
 * No comparison of the handler pointer is included.
 *
 * @return 1 if the two match, 0 if not
 */
static int dispatch_entry_matches(MONS_DISPATCH_TABLE_ENTRY *e,
                                  MON_CMD command,
                                  MON_OPT_TYPE opt_type)
{
  if ((command == MON_CMD_UNKNOWN) || (opt_type == OPT_TYPE_UNKNOWN))
    return 0; /* request is invalid */

  if ((e->command == MON_CMD_UNKNOWN) || (e->opt_type == OPT_TYPE_UNKNOWN))
    return 0; /* e1 is invalid */

  if (e->command != command)
    return 0; /* commands do not match */

  if (e->opt_type == opt_type)
    return 1; /* exact match */

  if ( (e->opt_type == OPT_TYPE_ANY) || (opt_type == OPT_TYPE_ANY) )
    return 1; /* one is a wildcard */

  return 0; /* commands matched but opt_types did not */
}

static MONS_HANDLER_FUNC *mons_find_handler(MONS_INSTANCE *mons, MON_CMD cmd, MON_OPT_TYPE opt_type)
{
  guint index;

  for (index=0; index < mons->handlers->len; index++) {
    if (dispatch_entry_matches(g_ptr_array_index(mons->handlers, index), cmd, opt_type))
      return g_ptr_array_index(mons->handlers, index);
  }
  return NULL;
}

/**
 * This calls every request handler that matches a command/opt_type,
 * gathering their results.
 *
 * @param element
 * @param data
 */
static void request_helper(void *element, void *data)
{
  MONS_DISPATCH_TABLE_ENTRY *entry = talloc_get_type_abort(element, MONS_DISPATCH_TABLE_ENTRY);
  struct request_helper_data *helper_data = data;
  struct handler_result result = {0};

  if (dispatch_entry_matches(entry, helper_data->command, helper_data->opt_type)) {
    result.rc = entry->handler(entry->cookie, &(result.json_data));
    result.opt_type = entry->opt_type;
    g_array_append_val(helper_data->results, result);
  }
}

