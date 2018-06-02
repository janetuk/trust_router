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

#include <talloc.h>
#include <jansson.h>

#include <tr_gss_names.h>
#include <trp_peer.h>
#include <tr_util.h>
#include <tr_json_util.h>

char *trp_peer_to_str(TALLOC_CTX *memctx, TRP_PEER *peer, const char *sep)
{
  if (sep==NULL)
    sep=", ";
  return talloc_asprintf(memctx,
                         "%s:%u%s0x%04X",
                         peer->server, peer->port, sep,
                         peer->linkcost);
}

/* helper for encoding to json */
static json_t *server_to_json_string(const char *server, int port)
{
  char *s = talloc_asprintf(NULL, "%s:%u", server, port);
  json_t *jstr = json_string(s);
  talloc_free(s);
  return jstr;
}

static json_t *last_attempt_to_json_string(TRP_PEER *peer)
{
  struct timespec ts_zero = {0, 0};
  struct timespec *last_conn_attempt;
  char *s = NULL;
  json_t *jstr = NULL;

  if (tr_cmp_timespec(trp_peer_get_last_conn_attempt(peer), &ts_zero) > 0) {
    s = timespec_to_str(trp_peer_get_last_conn_attempt(peer));

    if (s) {
      jstr = json_string(s);
      free(s);
    }
  }

  return jstr;
}

json_t *trp_peer_to_json(TRP_PEER *peer)
{
  json_t *peer_json = NULL;
  json_t *retval = NULL;

  peer_json = json_object();
  if (peer_json == NULL)
    goto cleanup;


  OBJECT_SET_OR_FAIL(peer_json, "server",
                     server_to_json_string(trp_peer_get_server(peer),
                                           trp_peer_get_port(peer)));
  OBJECT_SET_OR_FAIL(peer_json, "servicename",
                     tr_name_to_json_string(trp_peer_get_servicename(peer)));
  OBJECT_SET_OR_FAIL(peer_json, "linkcost",
                     json_integer(trp_peer_get_linkcost(peer)));
  OBJECT_SET_OR_FAIL(peer_json, "connected_to",
                     json_boolean(trp_peer_get_outgoing_status(peer) == PEER_CONNECTED));
  OBJECT_SET_OR_FAIL(peer_json, "connected_from",
                     json_boolean(trp_peer_get_incoming_status(peer) == PEER_CONNECTED));
  OBJECT_SET_OR_SKIP(peer_json, "last_connection_attempt",
                     last_attempt_to_json_string(peer));
  OBJECT_SET_OR_FAIL(peer_json, "allowed_credentials",
                     tr_gss_names_to_json_array(trp_peer_get_gss_names(peer)));
  OBJECT_SET_OR_FAIL(peer_json, "filters",
                     tr_filter_set_to_json(peer->filters));

  /* succeeded - set the return value and increment the reference count */
  retval = peer_json;
  json_incref(retval);

cleanup:
  if (peer_json)
    json_decref(peer_json);
  return retval;
}
