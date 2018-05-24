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

#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <dirent.h>
#include <talloc.h>

#include <tr_cfgwatch.h>
#include <tr_comm.h>
#include <tr_config.h>
#include <tr_gss_names.h>
#include <tr_debug.h>
#include <tr_filter.h>
#include <trust_router/tr_constraint.h>
#include <tr_idp.h>
#include <tr.h>
#include <trust_router/trp.h>

#if JANSSON_VERSION_HEX < 0x020500
#include "jansson_iterators.h"
#endif

TR_AAA_SERVER *tr_cfg_parse_one_aaa_server(TALLOC_CTX *mem_ctx, json_t *jaddr, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  TR_AAA_SERVER *aaa = NULL;

  if ((!jaddr) || (!json_is_string(jaddr))) {
    tr_debug("tr_cfg_parse_one_aaa_server: Bad parameters.");
    *rc = TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  aaa = tr_aaa_server_from_string(mem_ctx, json_string_value(jaddr));
  if (aaa == NULL) {
    tr_debug("tr_cfg_parse_one_aaa_server: Out of memory allocating AAA server.");
    *rc = TR_CFG_NOMEM;
    goto cleanup;
  }

  if (tr_aaa_server_get_hostname(aaa)->len == 0) {
    tr_debug("tr_cfg_parse_one_aaa_server: Empty hostname for AAA server not allowed");
    *rc = TR_CFG_NOPARSE;
    goto cleanup;
  }

  if ((tr_aaa_server_get_port(aaa) <= 0)
      || (tr_aaa_server_get_port(aaa) > 65535)) {
    tr_debug("tr_cfg_parse_one_aaa_server: Invalid AAA server port");
    *rc = TR_CFG_NOPARSE;
    goto cleanup;
  }

  /* success ! */
  *rc = TR_CFG_SUCCESS;
  talloc_steal(mem_ctx, aaa);

cleanup:
  if (*rc != TR_CFG_SUCCESS)
    aaa = NULL;
  talloc_free(tmp_ctx);
  return aaa;
}

static TR_AAA_SERVER *tr_cfg_parse_aaa_servers(TALLOC_CTX *mem_ctx, json_t *jaaas, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=NULL;
  TR_AAA_SERVER *aaa = NULL;
  TR_AAA_SERVER *temp_aaa = NULL;
  int i = 0;

  for (i = 0; i < json_array_size(jaaas); i++) {
    /* rc gets set in here */
    if (NULL == (temp_aaa = tr_cfg_parse_one_aaa_server(tmp_ctx, json_array_get(jaaas, i), rc))) {
      talloc_free(tmp_ctx);
      return NULL;
    }
    /* TBD -- IPv6 addresses */
    //    tr_debug("tr_cfg_parse_aaa_servers: Configuring AAA Server: ip_addr = %s.", inet_ntoa(temp_aaa->aaa_server_addr));
    temp_aaa->next = aaa;
    aaa = temp_aaa;
  }
  tr_debug("tr_cfg_parse_aaa_servers: Finished (rc=%d)", *rc);

  for (temp_aaa=aaa; temp_aaa!=NULL; temp_aaa=temp_aaa->next)
    talloc_steal(mem_ctx, temp_aaa);
  talloc_free(tmp_ctx);
  return aaa;
}

static TR_APC *tr_cfg_parse_one_apc(TALLOC_CTX *mem_ctx, json_t *japc, TR_CFG_RC *rc)
{
  TR_APC *apc=NULL;
  TR_NAME *name=NULL;

  *rc = TR_CFG_SUCCESS;         /* presume success */

  if ((!japc) || (!rc) || (!json_is_string(japc))) {
    tr_debug("tr_cfg_parse_one_apc: Bad parameters.");
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  apc=tr_apc_new(mem_ctx);
  if (apc==NULL) {
    tr_debug("tr_cfg_parse_one_apc: Out of memory.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  name=tr_new_name(json_string_value(japc));
  if (name==NULL) {
    tr_debug("tr_cfg_parse_one_apc: No memory for APC name.");
    tr_apc_free(apc);
    *rc = TR_CFG_NOMEM;
    return NULL;
  }
  tr_apc_set_id(apc, name); /* apc is now responsible for freeing the name */

  return apc;
}

TR_APC *tr_cfg_parse_apcs(TALLOC_CTX *mem_ctx, json_t *japcs, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_APC *apcs=NULL;
  TR_APC *new_apc=NULL;
  int ii=0;
  TR_CFG_RC call_rc=TR_CFG_ERROR;

  *rc = TR_CFG_SUCCESS;         /* presume success */

  if ((!japcs) || (!rc) || (!json_is_array(japcs))) {
    tr_debug("tr_cfg_parse_one_apc: Bad parameters.");
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  for (ii=0; ii<json_array_size(japcs); ii++) {
    new_apc=tr_cfg_parse_one_apc(tmp_ctx, json_array_get(japcs, ii), &call_rc);
    if ((call_rc!=TR_CFG_SUCCESS) || (new_apc==NULL)) {
      tr_debug("tr_cfg_parse_apcs: Error parsing APC %d.", ii+1);
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    }
    tr_apc_add(apcs, new_apc);
  }

  talloc_steal(mem_ctx, apcs);
  *rc=TR_CFG_SUCCESS;

cleanup:
  talloc_free(tmp_ctx);
  return apcs;
}

static TR_NAME *tr_cfg_parse_name(TALLOC_CTX *mem_ctx, json_t *jname, TR_CFG_RC *rc)
{
  TR_NAME *name=NULL;
  *rc=TR_CFG_ERROR;

  if ((jname==NULL) || (!json_is_string(jname))) {
    tr_err("tr_cfg_parse_name: name missing or not a string");
    *rc=TR_CFG_BAD_PARAMS;
    name=NULL;
  } else {
    name=tr_new_name(json_string_value(jname));
    if (name==NULL) {
      tr_err("tr_cfg_parse_name: could not allocate name");
      *rc=TR_CFG_NOMEM;
    } else {
      *rc=TR_CFG_SUCCESS;
    }
  }
  return name;
}

static int tr_cfg_parse_shared_config(json_t *jsc, TR_CFG_RC *rc)
{
  const char *shared=NULL;
  *rc=TR_CFG_SUCCESS;

  if ((jsc==NULL) ||
      (!json_is_string(jsc)) ||
      (NULL==(shared=json_string_value(jsc)))) {
    *rc=TR_CFG_BAD_PARAMS;
    return -1;
  }

  if (0==strcmp(shared, "no"))
    return 0;
  else if (0==strcmp(shared, "yes"))
    return 1;

  /* any other value is an error */
  tr_debug("tr_cfg_parse_shared_config: invalid shared_config value \"%s\" (should be \"yes\" or \"no\")",
           shared);
  *rc=TR_CFG_NOPARSE;
  return -1;
}

static TR_REALM_ORIGIN tr_cfg_realm_origin(json_t *jrealm)
{
  json_t *jremote=json_object_get(jrealm, "remote");
  const char *s=NULL;

  if (jremote==NULL)
    return TR_REALM_LOCAL;
  if (!json_is_string(jremote)) {
    tr_warning("tr_cfg_realm_origin: \"remote\" is not a string, assuming this is a local realm.");
    return TR_REALM_LOCAL;
  }
  s=json_string_value(jremote);
  if (strcasecmp(s, "yes")==0)
    return TR_REALM_REMOTE_INCOMPLETE;
  else if (strcasecmp(s, "no")!=0)
    tr_warning("tr_cfg_realm_origin: \"remote\" is neither 'yes' nor 'no', assuming this is a local realm.");

  return TR_REALM_LOCAL;
}

/* Parse the identity provider object from a realm and fill in the given TR_IDP_REALM. */
static TR_CFG_RC tr_cfg_parse_idp(TR_IDP_REALM *idp, json_t *jidp)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_APC *apcs=NULL;
  TR_AAA_SERVER *aaa=NULL;
  TR_CFG_RC rc=TR_CFG_ERROR;

  if (jidp==NULL)
    goto cleanup;

  idp->shared_config=tr_cfg_parse_shared_config(json_object_get(jidp, "shared_config"), &rc);
  if (rc!=TR_CFG_SUCCESS) {
    tr_err("tr_cfg_parse_idp: missing or malformed shared_config specification");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  apcs=tr_cfg_parse_apcs(tmp_ctx, json_object_get(jidp, "apcs"), &rc);
  if ((rc!=TR_CFG_SUCCESS) || (apcs==NULL)) {
    tr_err("tr_cfg_parse_idp: unable to parse APC");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  aaa=tr_cfg_parse_aaa_servers(idp, json_object_get(jidp, "aaa_servers"), &rc);
  if (rc!=TR_CFG_SUCCESS) {
    tr_err("tr_cfg_parse_idp: unable to parse AAA servers");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  tr_debug("tr_cfg_parse_idp: APC=\"%.*s\"",
           apcs->id->len,
           apcs->id->buf);

  /* done, fill in the idp structures */
  idp->apcs=apcs;
  talloc_steal(idp, apcs);
  idp->aaa_servers=aaa;
  rc=TR_CFG_SUCCESS;

cleanup:
  if (rc!=TR_CFG_SUCCESS) {
    if (apcs!=NULL)
      tr_apc_free(apcs);
    if (aaa!=NULL)
      tr_aaa_server_free(aaa);
  }

  talloc_free(tmp_ctx);
  return rc;
}

/* parses idp realm */
static TR_IDP_REALM *tr_cfg_parse_one_idp_realm(TALLOC_CTX *mem_ctx, json_t *jrealm, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_IDP_REALM *realm=NULL;
  TR_CFG_RC call_rc=TR_CFG_ERROR;

  *rc=TR_CFG_ERROR; /* default to error if not set */

  if ((!jrealm) || (!rc)) {
    tr_err("tr_cfg_parse_one_idp_realm: Bad parameters.");
    if (rc)
      *rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  if (NULL==(realm=tr_idp_realm_new(tmp_ctx))) {
    tr_err("tr_cfg_parse_one_idp_realm: could not allocate idp realm.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  realm->origin=tr_cfg_realm_origin(jrealm);
  if (realm->origin!=TR_REALM_LOCAL) {
    tr_debug("tr_cfg_parse_one_idp_realm: realm is remote, should not have full IdP info.");
    *rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  /* must have a name */
  realm->realm_id=tr_cfg_parse_name(realm,
                                    json_object_get(jrealm, "realm"),
                                    &call_rc);
  if ((call_rc!=TR_CFG_SUCCESS) || (realm->realm_id==NULL)) {
    tr_err("tr_cfg_parse_one_idp_realm: could not parse realm name");
    *rc=TR_CFG_NOPARSE;
    goto cleanup;
  }
  tr_debug("tr_cfg_parse_one_idp_realm: realm_id=\"%.*s\"",
           realm->realm_id->len,
           realm->realm_id->buf);

  call_rc=tr_cfg_parse_idp(realm, json_object_get(jrealm, "identity_provider"));
  if (call_rc!=TR_CFG_SUCCESS) {
    tr_err("tr_cfg_parse_one_idp_realm: could not parse identity_provider.");
    *rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  *rc=TR_CFG_SUCCESS;

cleanup:
  if (*rc==TR_CFG_SUCCESS)
    talloc_steal(mem_ctx, realm);
  else {
    talloc_free(realm);
    realm=NULL;
  }

  talloc_free(tmp_ctx);
  return realm;
}

/* Determine whether the realm is an IDP realm */
static int tr_cfg_is_idp_realm(json_t *jrealm)
{
  /* If a realm spec contains an identity_provider, it's an IDP realm. */
  if (NULL != json_object_get(jrealm, "identity_provider"))
    return 1;
  else
    return 0;
}

static TR_IDP_REALM *tr_cfg_parse_one_remote_realm(TALLOC_CTX *mem_ctx, json_t *jrealm, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_IDP_REALM *realm=talloc(mem_ctx, TR_IDP_REALM);

  *rc=TR_CFG_ERROR; /* default to error if not set */

  if ((!jrealm) || (!rc)) {
    tr_err("tr_cfg_parse_one_remote_realm: Bad parameters.");
    if (rc)
      *rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  if (NULL==(realm=tr_idp_realm_new(tmp_ctx))) {
    tr_err("tr_cfg_parse_one_remote_realm: could not allocate idp realm.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  /* must have a name */
  realm->realm_id=tr_cfg_parse_name(realm,
                                    json_object_get(jrealm, "realm"),
                                    rc);
  if ((*rc!=TR_CFG_SUCCESS) || (realm->realm_id==NULL)) {
    tr_err("tr_cfg_parse_one_remote_realm: could not parse realm name");
    *rc=TR_CFG_NOPARSE;
    goto cleanup;
  }
  tr_debug("tr_cfg_parse_one_remote_realm: realm_id=\"%.*s\"",
           realm->realm_id->len,
           realm->realm_id->buf);

  realm->origin=tr_cfg_realm_origin(jrealm);
  *rc=TR_CFG_SUCCESS;

cleanup:
  if (*rc==TR_CFG_SUCCESS)
    talloc_steal(mem_ctx, realm);
  else {
    talloc_free(realm);
    realm=NULL;
  }

  talloc_free(tmp_ctx);
  return realm;
}

static int tr_cfg_is_remote_realm(json_t *jrealm)
{
  return (tr_cfg_realm_origin(jrealm)!=TR_REALM_LOCAL);
}

/* Parse any idp realms in the j_realms object. Ignores other realm types. */
TR_IDP_REALM *tr_cfg_parse_idp_realms(TALLOC_CTX *mem_ctx, json_t *jrealms, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_IDP_REALM *realms=NULL;
  TR_IDP_REALM *new_realm=NULL;
  json_t *this_jrealm=NULL;
  int ii=0;

  *rc=TR_CFG_ERROR;
  if ((jrealms==NULL) || (!json_is_array(jrealms))) {
    tr_err("tr_cfg_parse_idp_realms: realms not an array");
    *rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  for (ii=0; ii<json_array_size(jrealms); ii++) {
    this_jrealm=json_array_get(jrealms, ii);
    if (tr_cfg_is_idp_realm(this_jrealm)) {
      new_realm=tr_cfg_parse_one_idp_realm(tmp_ctx, this_jrealm, rc);
      if ((*rc)!=TR_CFG_SUCCESS) {
        tr_err("tr_cfg_parse_idp_realms: error decoding realm entry %d", ii+1);
        *rc=TR_CFG_NOPARSE;
        goto cleanup;
      }
      tr_idp_realm_add(realms, new_realm);
    } else if (tr_cfg_is_remote_realm(this_jrealm)) {
      new_realm=tr_cfg_parse_one_remote_realm(tmp_ctx, this_jrealm, rc);
      if ((*rc)!=TR_CFG_SUCCESS) {
        tr_err("tr_cfg_parse_idp_realms: error decoding remote realm entry %d", ii+1);
        *rc=TR_CFG_NOPARSE;
        goto cleanup;
      }
      tr_idp_realm_add(realms, new_realm);
    }
  }

  *rc=TR_CFG_SUCCESS;
  talloc_steal(mem_ctx, realms);

cleanup:
  talloc_free(tmp_ctx);
  return realms;
}
