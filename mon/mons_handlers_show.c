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

/* Handlers for monitoring "show" requests */

#include <jansson.h>
#include <talloc.h>

#include <tr_debug.h>
#include <mon_internal.h>
#include "mons_handlers.h"

typedef json_t *(MONS_SHOW_FUNC)(MONS_INSTANCE *mons);

/* prototypes for the dispatch table */
static json_t *handle_show_version(MONS_INSTANCE *mons);

struct dispatch_table_entry {
  MON_OPT_TYPE opt_type;
  MONS_SHOW_FUNC *handler;
};

struct dispatch_table_entry dispatch_table[] = {
    {OPT_TYPE_SHOW_VERSION, handle_show_version},
    {OPT_TYPE_SHOW_SERIAL, NULL},
    {OPT_TYPE_SHOW_UPTIME, NULL},
    {OPT_TYPE_SHOW_TID_REQ_COUNT, NULL},
    {OPT_TYPE_SHOW_TID_REQ_PENDING, NULL},
    {OPT_TYPE_SHOW_ROUTES, NULL},
    {OPT_TYPE_SHOW_COMMUNITIES, NULL},
    {OPT_TYPE_UNKNOWN} /* must be the last entry */
};

/**
 * Should we include this opt_type in our response to this request?
 *
 * Returns 1 if the opt_type is in the options list, or if the options list
 * is empty.
 *
 * @param opt_type
 * @param req
 * @return 1 if the opt_type should be included, else 0
 */
static int opt_requested(MON_OPT_TYPE opt_type, MON_REQ *req)
{
  size_t ii;

  /* empty options list is a wildcard - return everything */
  if (mon_req_opt_count(req) == 0)
    return 1;

  /* check whether this opt_type is in the list */
  for (ii=0; ii<mon_req_opt_count(req); ii++) {
    if (opt_type == mon_req_opt_index(req, ii)->type)
      return 1;
  }
  return 0;
}

MON_RESP *mons_handle_show(TALLOC_CTX *mem_ctx, MONS_INSTANCE *mons, MON_REQ *req)
{
  struct dispatch_table_entry *entry = NULL;
  MON_RESP *resp = NULL;
  json_t *payload = NULL; /* entire payload */
  json_t *payload_item = NULL; /* payload for a single option */

  tr_debug("mons_handle_show: Handling a request");

  /* Start off by allocating our response with a generic error message */
  resp = mon_resp_new(mem_ctx,
                      MON_RESP_ERROR,
                      "Error processing show request",
                      NULL);
  if (resp == NULL) {
    /* we can't respond, just return */
    tr_crit("mons_handle_show: Error allocating response structure.");
    goto cleanup;
  }

  /* Now get a JSON object for our return payload */
  payload = json_object();
  if (payload == NULL) {
    tr_crit("mons_handle_show: Error allocating response payload.");
    goto cleanup; /* This will return the generic error message set earlier */
  }

  tr_debug("mons_handle_show: Processing options");

  /* Now step through the dispatch table. Call each requested option type. */
  for (entry = dispatch_table; entry->opt_type != OPT_TYPE_UNKNOWN; entry++) {
    if (! opt_requested(entry->opt_type, req)) {
      tr_debug("mons_handle_show: Not including %s in response",
               mon_opt_type_to_string(entry->opt_type));
    } else {
      /* This option is needed. Add its response to our payload. */
      if (entry->handler == NULL) {
        tr_debug("mons_handle_show: Would include %s in response, but its handler is null",
                 mon_opt_type_to_string(entry->opt_type));
        continue;
      }

      tr_debug("mons_handle_show: Including %s in response",
               mon_opt_type_to_string(entry->opt_type));

      payload_item = entry->handler(mons);
      if (payload_item == NULL) {
        tr_err("mons_handle_show: Error processing option %s", mon_opt_type_to_string(entry->opt_type));
        goto cleanup;
      }
      /* this steals the reference to payload_item */
      json_object_set_new(payload,
                          mon_opt_type_to_string(entry->opt_type),
                          payload_item);
    }
  }

  /* If we get here, then we successfully processed the request. Return a successful reply. */
  if (mon_resp_set_message(resp, "success") == 0) {
    /* Failed to set the response message to success - fail ironically */
    tr_crit("mons_handle_show: Error setting response message to 'success'");
    goto cleanup;
  }

  /* Attach the accumulated payload to the response */
  if (json_object_size(payload) > 0)
    mon_resp_set_payload(resp, payload);

  resp->code = MON_RESP_SUCCESS; /* at last... */

cleanup:
  if (payload)
    json_decref(payload);
  return resp;
}


static json_t *handle_show_version(MONS_INSTANCE *mons)
{
  return json_string(PACKAGE_VERSION);
}