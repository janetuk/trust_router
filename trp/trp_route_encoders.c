/*
 * Copyright (c) 2016-2018, JANET(UK)
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

#include <stdlib.h>
#include <string.h>

#include <talloc.h>
#include <jansson.h>

#include <tr_name_internal.h>
#include <trp_route.h>
#include <trp_internal.h>
#include <trp_rtable.h>
#include <trust_router/trp.h>
#include <tr_util.h>

/* Pretty print a route table entry to a newly allocated string. If sep is NULL,
 * returns comma+space separated string. */
char *trp_route_to_str(TALLOC_CTX *mem_ctx, TRP_ROUTE *entry, const char *sep)
{
  char *comm=tr_name_strdup(entry->comm);
  char *realm=tr_name_strdup(entry->realm);
  char *peer=tr_name_strdup(entry->peer);
  char *trust_router=tr_name_strdup(entry->trust_router);
  char *next_hop=tr_name_strdup(entry->next_hop);
  char *expiry=timespec_to_str(entry->expiry);
  char *result=NULL;

  if (sep==NULL)
    sep=", ";

  result=talloc_asprintf(mem_ctx,
                         "%s%s%s%s%s%s%u%s%s%s%s%s%u%s%u%s%s%s%u",
                         comm, sep,
                         realm, sep,
                         peer, sep,
                         entry->metric, sep,
                         trust_router, sep,
                         next_hop, sep,
                         entry->selected, sep,
                         entry->local, sep,
                         expiry, sep,
                         entry->triggered);
  free(comm);
  free(realm);
  free(peer);
  free(trust_router);
  free(next_hop);
  free(expiry);
  return result;
}

/* helper for below */
#define OBJECT_SET_OR_FAIL(jobj, key, val)     \
do {                                           \
  if (val)                                     \
    json_object_set_new((jobj),(key),(val));   \
  else                                         \
    goto cleanup;                              \
} while (0)

json_t *trp_route_to_json(TRP_ROUTE *route)
{
  json_t *route_json = NULL;
  char *expires = NULL;
  struct timespec ts_zero = {0, 0};

  route_json = json_object();
  if (route_json == NULL)
    return NULL;

  if (tr_cmp_timespec(trp_route_get_expiry(route), &ts_zero) == 0) {
    expires = strdup("");
  } else {
    expires = timespec_to_str(route->expiry);
    if (expires == NULL) {
      json_decref(route_json);
      return NULL;
    }
  }

  OBJECT_SET_OR_FAIL(route_json, "community", tr_name_to_json_string(route->comm));
  OBJECT_SET_OR_FAIL(route_json, "realm", tr_name_to_json_string(route->realm));
  OBJECT_SET_OR_FAIL(route_json, "peer", tr_name_to_json_string(route->peer));
  OBJECT_SET_OR_FAIL(route_json, "metric", json_integer(route->metric));
  OBJECT_SET_OR_FAIL(route_json, "trust_router", tr_name_to_json_string(route->trust_router));
  OBJECT_SET_OR_FAIL(route_json, "next_hop", tr_name_to_json_string(route->next_hop));
  OBJECT_SET_OR_FAIL(route_json, "selected", json_boolean(route->selected));
  OBJECT_SET_OR_FAIL(route_json, "local", json_boolean(route->local));
  OBJECT_SET_OR_FAIL(route_json, "expires", json_string(expires));

cleanup:
  free(expires);
  return route_json;
}