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

#include <tr_gss_names.h>
#include <tr_rp_client.h>
#include <tr_json_util.h>

static json_t *tr_rp_client_to_json(TR_RP_CLIENT *rp_client)
{
  json_t *client_json = NULL;
  json_t *retval = NULL;

  client_json = json_object();
  if (client_json == NULL)
    goto cleanup;

  OBJECT_SET_OR_FAIL(client_json, "gss_names", tr_gss_names_to_json_array(rp_client->gss_names));
  OBJECT_SET_OR_FAIL(client_json, "filters", tr_filter_set_to_json(rp_client->filters));
  
  /* succeeded - set the return value and increment the reference count */
  retval = client_json;
  json_incref(retval);

cleanup:
  if (client_json)
    json_decref(client_json);
  return retval;
}

json_t *tr_rp_clients_to_json(TR_RP_CLIENT *rp_clients)
{
  json_t *jarray = json_array();
  json_t *retval = NULL;
  TR_RP_CLIENT_ITER *iter = tr_rp_client_iter_new(NULL);
  TR_RP_CLIENT *rp_client = NULL;

  if ((jarray == NULL) || (iter == NULL))
    goto cleanup;

  for (rp_client = tr_rp_client_iter_first(iter, rp_clients);
       rp_client != NULL;
       rp_client = tr_rp_client_iter_next(iter)) {
    ARRAY_APPEND_OR_FAIL(jarray, tr_rp_client_to_json(rp_client));
  }

  /* succeeded - set the return value and increment the reference count */
  retval = jarray;
  json_incref(retval);

cleanup:
  if (jarray)
    json_decref(jarray);

  if (iter)
    tr_rp_client_iter_free(iter);

  return retval;
}
