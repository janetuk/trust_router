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

#include <talloc.h>
#include <time.h>
#include <jansson.h>

#include <tr_name_internal.h>
#include <tr_idp.h>
#include <tr_config.h>
#include <tr_debug.h>

static char *tr_aaa_server_to_str(TALLOC_CTX *mem_ctx, TR_AAA_SERVER *aaa)
{
  return talloc_strndup(mem_ctx, aaa->hostname->buf, aaa->hostname->len);
}


char *tr_idp_realm_to_str(TALLOC_CTX *mem_ctx, TR_IDP_REALM *idp)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  char **s_aaa=NULL, *aaa_servers=NULL;
  char **s_apc=NULL, *apcs=NULL;
  int ii=0, aaa_servers_strlen=0, apcs_strlen=0;
  int n_aaa_servers=tr_idp_realm_aaa_server_count(idp);
  int n_apcs=tr_idp_realm_apc_count(idp);
  TR_AAA_SERVER *aaa=NULL;
  TR_APC *apc=NULL;
  char *result=NULL;

  /* get the AAA servers */
  if (n_aaa_servers<=0)
    aaa_servers=talloc_strdup(tmp_ctx, "");
  else {
    s_aaa=talloc_array(tmp_ctx, char *, n_aaa_servers);
    for (aaa=idp->aaa_servers,ii=0; aaa!=NULL; aaa=aaa->next,ii++) {
      s_aaa[ii]=tr_aaa_server_to_str(s_aaa, aaa);
      aaa_servers_strlen+=strlen(s_aaa[ii]);
    }

    /* add space for comma-space separators */
    aaa_servers_strlen+=2*(n_aaa_servers-1);

    aaa_servers=talloc_array(tmp_ctx, char, aaa_servers_strlen+1);
    aaa_servers[0]='\0';
    for (ii=0; ii<n_aaa_servers; ii++) {
      strcat(aaa_servers, s_aaa[ii]);
      if (ii<(n_aaa_servers-1))
        strcat(aaa_servers, ", ");
    }
    talloc_free(s_aaa);
  }

  /* get the APCs */
  if (n_apcs<=0)
    apcs=talloc_strdup(tmp_ctx, "");
  else {
    s_apc=talloc_array(tmp_ctx, char *, n_apcs);
    for (apc=idp->apcs,ii=0; apc!=NULL; apc=apc->next,ii++) {
      s_apc[ii]=tr_apc_to_str(s_apc, apc);
      apcs_strlen+=strlen(s_apc[ii]);
    }

    /* add space for comma-space separators */
    apcs_strlen+=2*(n_apcs-1);

    apcs=talloc_array(tmp_ctx, char, apcs_strlen+1);
    apcs[0]='\0';
    for (ii=0; ii<n_apcs; ii++) {
      strcat(apcs, s_apc[ii]);
      if (ii<(n_apcs-1))
        strcat(apcs, ", ");
    }
    talloc_free(s_apc);
  }

  result=talloc_asprintf(mem_ctx,
                         "IDP realm: \"%.*s\""
                         "  shared: %s"
                         "  local: %s"
                         "  AAA servers: %s"
                         "  APCs: %s",
                         idp->realm_id->len, idp->realm_id->buf,
                         (idp->shared_config)?"yes":"no",
                         (idp->origin==TR_REALM_LOCAL)?"yes":"no",
                         aaa_servers,
                         apcs);
  talloc_free(tmp_ctx);
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

#define ARRAY_APPEND_OR_FAIL(jary, val)        \
do {                                           \
  if (val)                                     \
    json_array_append_new((jary),(val));       \
  else                                         \
    goto cleanup;                              \
} while (0)

static json_t *tr_apcs_to_json(TR_APC *apcs)
{
  json_t *jarray = json_array();
  json_t *retval = NULL;
  TR_APC_ITER *iter = tr_apc_iter_new(NULL);
  TR_APC *apc = NULL;

  if ((jarray == NULL) || (iter == NULL))
    goto cleanup;

  apc = tr_apc_iter_first(iter, apcs);
  while (apc) {
    ARRAY_APPEND_OR_FAIL(jarray, tr_name_to_json_string(tr_apc_get_id(apc)));
    apc = tr_apc_iter_next(iter);
  }

  /* success */
  retval = jarray;
  json_incref(retval);

cleanup:
  if (jarray)
    json_decref(jarray);

  return retval;
}

static json_t *tr_aaa_server_to_json(TR_AAA_SERVER *aaa)
{
  char *hostname = tr_name_strdup(aaa->hostname);
  char *s = NULL;
  json_t *jstr = NULL;

  if (hostname == NULL)
    return NULL;

  s = talloc_asprintf(NULL, "%s:%d", hostname, TID_PORT);
  if (s) {
    jstr = json_string(s);
    talloc_free(s);
  }
  return jstr;
}

static json_t *tr_aaa_servers_to_json(TR_AAA_SERVER *aaas)
{
  json_t *jarray = json_array();
  json_t *retval = NULL;
  TR_AAA_SERVER_ITER *iter = tr_aaa_server_iter_new(NULL);
  TR_AAA_SERVER *aaa = NULL;

  if ((jarray == NULL) || (iter == NULL))
    goto cleanup;

  aaa = tr_aaa_server_iter_first(iter, aaas);
  while (aaa) {
    ARRAY_APPEND_OR_FAIL(jarray, tr_aaa_server_to_json(aaa));
    aaa = tr_aaa_server_iter_next(iter);
  }

  /* success */
  retval = jarray;
  json_incref(retval);

cleanup:
  if (jarray)
    json_decref(jarray);

  return retval;
}

static json_t *tr_idp_realm_to_json(TR_IDP_REALM *idp)
{
  json_t *idp_json = json_object();
  json_t *retval = NULL;

  if (idp_json == NULL)
    goto cleanup;


  /* success */
  retval = idp_json;
  json_incref(retval);

  OBJECT_SET_OR_FAIL(idp_json, "realm",
                     tr_name_to_json_string(tr_idp_realm_get_id(idp)));
  OBJECT_SET_OR_FAIL(idp_json, "discovered",
                     json_boolean(idp->origin == TR_REALM_DISCOVERED));
  OBJECT_SET_OR_FAIL(idp_json, "apcs",
                     tr_apcs_to_json(tr_idp_realm_get_apcs(idp)));
  OBJECT_SET_OR_FAIL(idp_json, "aaa_servers",
                     tr_aaa_servers_to_json(idp->aaa_servers));
  OBJECT_SET_OR_FAIL(idp_json, "shared_config",
                     json_boolean(idp->shared_config));
cleanup:
  if (idp_json)
    json_decref(idp_json);

  return retval;
}

json_t *tr_idp_realms_to_json(TR_IDP_REALM *idps)
{
  {
    json_t *jarray = json_array();
    json_t *retval = NULL;
    TR_IDP_REALM *this = NULL;

    if (jarray == NULL)
      goto cleanup;

    for (this=idps; this != NULL; this=this->next)
      ARRAY_APPEND_OR_FAIL(jarray, tr_idp_realm_to_json(this));

    /* success */
    retval = jarray;
    json_incref(retval);

  cleanup:
    if (jarray)
      json_decref(jarray);

    return retval;
  }

}