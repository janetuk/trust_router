/*
 * Copyright (c) 2012-2018, JANET(UK)
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

#include <jansson.h>
#include <tr_idp.h>
#include <tr_comm.h>
#include <tr_util.h>
#include <tr_debug.h>

static json_t *expiry_to_json_string(TR_COMM_MEMB *memb)
{
  struct timespec ts = {0}; /* initialization to zero is important */
  char *s = NULL;
  json_t *jstr = NULL;

  if (tr_cmp_timespec(tr_comm_memb_get_expiry(memb), &ts) > 0) {
    if (tr_comm_memb_get_expiry_realtime(memb, &ts) == NULL)
      s = strdup("error");
    else
      s = timespec_to_str(&ts);

    if (s) {
      jstr = json_string(s);
      free(s);
    }
  }

  return jstr;
}

/**
 * Get the provenance from the member, handling empty provenance safely
 */
static json_t *provenance_to_json(TR_COMM_MEMB *memb)
{
  json_t *prov = tr_comm_memb_get_provenance(memb);

  if (prov) {
    json_incref(prov);
    return prov;
  } else {
    return json_array();
  }
}

/* helper for below */
#define OBJECT_SET_OR_FAIL(jobj, key, val)     \
do {                                           \
  if (val)                                     \
    json_object_set_new((jobj),(key),(val));   \
  else                                         \
    goto cleanup;                              \
} while (0)

#define ARRAY_APPEND_OR_FAIL(jary, val)        \
do {                                           \
  if (val)                                     \
    json_array_append_new((jary),(val));       \
  else                                         \
    goto cleanup;                              \
} while (0)

static json_t *tr_comm_memb_to_json(TR_COMM_MEMB *memb)
{
  json_t *memb_json = NULL;
  json_t *retval = NULL;

  memb_json = json_object();
  if (memb_json == NULL)
    goto cleanup;

  if (tr_comm_memb_get_origin(memb) == NULL) {
    OBJECT_SET_OR_FAIL(memb_json, "origin", json_string("file"));
  } else {
    OBJECT_SET_OR_FAIL(memb_json, "origin",
                       tr_name_to_json_string(tr_comm_memb_get_origin(memb)));
    OBJECT_SET_OR_FAIL(memb_json, "provenance",
                       provenance_to_json(memb));
    OBJECT_SET_OR_FAIL(memb_json, "expires",
                       expiry_to_json_string(memb));
    OBJECT_SET_OR_FAIL(memb_json, "announce_interval",
                       json_integer(tr_comm_memb_get_interval(memb)));
    OBJECT_SET_OR_FAIL(memb_json, "times_expired",
                       json_integer(tr_comm_memb_get_times_expired(memb)));
  }

  /* succeeded - set the return value and increment the reference count */
  retval = memb_json;
  json_incref(retval);

cleanup:
  if (memb_json)
    json_decref(memb_json);
  return retval;
}

/**
 * Summarize the different reasons we believe a realm belongs to a community
 */
static json_t *tr_comm_memb_sources_to_json(TR_COMM_MEMB *first_memb)
{
  json_t *jarray = NULL;
  json_t *retval = NULL;
  TR_COMM_ITER *iter = NULL;
  TR_COMM_MEMB *memb = NULL;

  jarray = json_array();
  if (jarray == NULL)
    goto cleanup;

  iter = tr_comm_iter_new(NULL);
  if (iter == NULL)
    goto cleanup;

  /* Iterate over all the memberships for this realm/comm pair that come from different origins */
  memb = tr_comm_memb_iter_first(iter, first_memb);
  while (memb) {
    ARRAY_APPEND_OR_FAIL(jarray, tr_comm_memb_to_json(memb));
    memb = tr_comm_memb_iter_next(iter);
  }

  /* success */
  retval = jarray;
  json_incref(retval);

cleanup:
  if (jarray)
    json_decref(jarray);
  if (iter)
    talloc_free(iter);
  return retval;
}

static json_t *tr_comm_realms_to_json(TR_COMM_TABLE *ctable, TR_NAME *comm_name, TR_REALM_ROLE role)
{
  json_t *jarray = json_array();
  json_t *realm_json = NULL;
  json_t *retval = NULL;
  TR_COMM_ITER *iter = NULL;
  TR_REALM *realm = NULL;
  TR_COMM_MEMB *memb = NULL;

  iter = tr_comm_iter_new(NULL);
  realm = tr_realm_iter_first(iter, ctable, comm_name);

  /* Do not display the full realm json here, only the name and info relevant to the community listing */
  while(realm) {
    if (realm->role == role) {
      realm_json = json_object();
      OBJECT_SET_OR_FAIL(realm_json, "realm",
                         tr_name_to_json_string(tr_realm_get_id(realm)));
      memb = tr_comm_table_find_idp_memb(ctable,
                                         tr_realm_get_id(realm),
                                         comm_name);
      OBJECT_SET_OR_FAIL(realm_json, "sources",
                         tr_comm_memb_sources_to_json(memb));
      json_array_append_new(jarray, realm_json);
      realm_json = NULL; /* so we don't free this twice during cleanup */
    }
    realm = tr_realm_iter_next(iter);
  }

  /* Success - increment the reference count so return value survives */
  retval = jarray;
  json_incref(retval);

cleanup:
  if (jarray)
    json_decref(jarray);

  if (realm_json)
    json_decref(realm_json);

  if (iter)
    tr_comm_iter_free(iter);

  return retval;
}

static json_t *tr_comm_to_json(TR_COMM_TABLE *ctable, TR_COMM *comm)
{
  json_t *comm_json = NULL;
  json_t *retval = NULL;

  comm_json = json_object();
  if (comm_json == NULL)
    goto cleanup;

  OBJECT_SET_OR_FAIL(comm_json, "type",
                     json_string(tr_comm_type_to_str(tr_comm_get_type(comm))));
  if (tr_comm_get_type(comm) == TR_COMM_APC) {
    OBJECT_SET_OR_FAIL(comm_json, "expiration_interval",
                       json_integer(comm->expiration_interval));
  } else {
    /* just get the first apc */
    OBJECT_SET_OR_FAIL(comm_json, "apc",
                       tr_name_to_json_string(
                           tr_apc_get_id(
                               tr_comm_get_apcs(comm))));
  }
  OBJECT_SET_OR_FAIL(comm_json, "name",
                     tr_name_to_json_string(tr_comm_get_id(comm)));
  if (tr_comm_get_owner_realm(comm)) {
    OBJECT_SET_OR_FAIL(comm_json, "owner_realm",
                     tr_name_to_json_string(tr_comm_get_owner_realm(comm)));
  }
  if (tr_comm_get_owner_contact(comm)) {
    OBJECT_SET_OR_FAIL(comm_json, "owner_contact",
                       tr_name_to_json_string(tr_comm_get_owner_contact(comm)));
  }
  OBJECT_SET_OR_FAIL(comm_json, "idp_realms",
                     tr_comm_realms_to_json(ctable, tr_comm_get_id(comm), TR_ROLE_IDP));
  OBJECT_SET_OR_FAIL(comm_json, "rp_realms",
                     tr_comm_realms_to_json(ctable, tr_comm_get_id(comm), TR_ROLE_RP));

  /* succeeded - set the return value and increment the reference count */
  retval = comm_json;
  json_incref(retval);

  cleanup:
  if (comm_json)
    json_decref(comm_json);
  return retval;
}

json_t *tr_comm_table_to_json(TR_COMM_TABLE *ctable)
{
  json_t *ctable_json = NULL;
  json_t *retval = NULL;
  json_t *comm_json = NULL;
  TR_COMM_ITER *iter = NULL;
  TR_COMM *comm = NULL;

  ctable_json = json_array();
  if (ctable_json == NULL)
    goto cleanup;

  iter = tr_comm_iter_new(NULL);
  if (iter == NULL)
    goto cleanup;

  /* Iterate over communities in the table */
  comm = tr_comm_table_iter_first(iter, ctable);
  while (comm) {
    comm_json = tr_comm_to_json(ctable, comm);

    if (comm_json == NULL)
      goto cleanup;

    json_array_append_new(ctable_json, comm_json);
    comm = tr_comm_table_iter_next(iter);
  }

  /* succeeded - set the return value and increment the reference count */
  retval = ctable_json;
  json_incref(retval);

cleanup:
  if (iter)
    tr_comm_iter_free(iter);

  if (ctable_json)
    json_decref(ctable_json);

  return retval;
 
}