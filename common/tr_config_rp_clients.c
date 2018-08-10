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
#include <tr_constraint_internal.h>
#include <tr_idp.h>
#include <tr.h>
#include <trust_router/trp.h>

#if JANSSON_VERSION_HEX < 0x020500
#include "jansson_iterators.h"
#endif


TR_CFG_RC tr_cfg_parse_gss_names(TALLOC_CTX *mem_ctx, json_t *jgss_names, TR_GSS_NAMES **gssn_out)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_GSS_NAMES *gn=NULL;
  json_t *jname=NULL;
  size_t ii=0;
  TR_NAME *name=NULL;
  TR_CFG_RC rc = TR_CFG_ERROR;

  if (jgss_names==NULL) {
    tr_err("tr_cfg_parse_gss_names: Bad parameters.");
    rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  if (!json_is_array(jgss_names)) {
    tr_err("tr_cfg_parse_gss_names: gss_names not an array.");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  gn=tr_gss_names_new(tmp_ctx);
  for (ii=0; ii<json_array_size(jgss_names); ii++) {
    jname=json_array_get(jgss_names, ii);
    if (!json_is_string(jname)) {
      tr_err("tr_cfg_parse_gss_names: Encountered non-string gss name.");
      rc=TR_CFG_NOPARSE;
      goto cleanup;
    }

    name=tr_new_name(json_string_value(jname));
    if (name==NULL) {
      tr_err("tr_cfg_parse_gss_names: Out of memory allocating gss name.");
      rc=TR_CFG_NOMEM;
      goto cleanup;
    }

    if (tr_gss_names_add(gn, name)!=0) {
      tr_free_name(name);
      tr_err("tr_cfg_parse_gss_names: Unable to add gss name to RP client.");
      rc=TR_CFG_ERROR;
      goto cleanup;
    }
  }

  *gssn_out = gn;
  talloc_steal(mem_ctx, *gssn_out);
  rc=TR_CFG_SUCCESS;

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

/* default filter accepts realm and *.realm */
static TR_FILTER_SET *tr_cfg_default_filters(TALLOC_CTX *mem_ctx, TR_NAME *realm, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_FILTER *filt=NULL;
  TR_FLINE *fline = NULL;
  TR_FSPEC *fspec = NULL;
  TR_FILTER_SET *filt_set=NULL;
  TR_CONSTRAINT *cons=NULL;
  TR_NAME *name=NULL;
  TR_NAME *n_prefix=tr_new_name("*.");
  TR_NAME *n_rp_realm_1=tr_new_name("rp_realm");
  TR_NAME *n_rp_realm_2=tr_new_name("rp_realm");
  TR_NAME *n_domain=tr_new_name("domain");
  TR_NAME *n_realm=tr_new_name("realm");


  if ((realm==NULL) || (rc==NULL)) {
    tr_debug("tr_cfg_default_filters: invalid arguments.");
    if (rc!=NULL)
      *rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  if ((n_prefix==NULL) ||
      (n_rp_realm_1==NULL) ||
      (n_rp_realm_2==NULL) ||
      (n_domain==NULL) ||
      (n_realm==NULL)) {
    tr_debug("tr_cfg_default_filters: unable to allocate names.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  filt=tr_filter_new(tmp_ctx);
  if (filt==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate filter.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  tr_filter_set_type(filt, TR_FILTER_TYPE_TID_INBOUND);

  fline = tr_fline_new(tmp_ctx);
  if (fline==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate filter line.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  fline->action=TR_FILTER_ACTION_ACCEPT;
  
  fspec=tr_fspec_new(tmp_ctx);
  fspec->field=n_rp_realm_1;
  n_rp_realm_1=NULL; /* we don't own this name any more */

  name=tr_dup_name(realm);
  if (NULL == name) {
    tr_debug("tr_cfg_default_filters: could not allocate realm name.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  if (NULL == tr_fspec_add_match(fspec, name)) {
    tr_debug("tr_cfg_default_filters: could not add realm name to filter spec.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  name=NULL; /* we no longer own the name */

  if (tr_fline_add_spec(fline, fspec) == NULL) {
    tr_debug("tr_cfg_default_filters: could not add first spec to filter line");
    *rc = TR_CFG_NOMEM;
    goto cleanup;
  }

  /* now do the wildcard name */
  fspec=tr_fspec_new(tmp_ctx);
  fspec->field=n_rp_realm_2;
  n_rp_realm_2=NULL; /* we don't own this name any more */

  if (NULL == (name=tr_name_cat(n_prefix, realm))) {
    tr_debug("tr_cfg_default_filters: could not allocate wildcard realm name.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  if (NULL == tr_fspec_add_match(fspec, name)) {
    tr_debug("tr_cfg_default_filters: could not add wildcard realm name for filter spec.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  name=NULL; /* we no longer own the name */

  if (tr_fline_add_spec(fline, fspec) == NULL) {
    tr_debug("tr_cfg_default_filters: could not add second spec to filter line");
    *rc = TR_CFG_NOMEM;
    goto cleanup;
  }

  /* domain constraint */
  if (NULL==(cons=tr_constraint_new(fline))) {
    tr_debug("tr_cfg_default_filters: could not allocate domain constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  cons->type=n_domain;
  n_domain=NULL; /* belongs to the constraint now */
  name=tr_dup_name(realm);
  if (name==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate realm name for domain constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  if (NULL == tr_constraint_add_match(cons, name)) {
    tr_debug("tr_cfg_default_filters: could not add realm name for domain constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  name=tr_name_cat(n_prefix, realm);
  if (name==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate wildcard realm name for domain constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  if (NULL == tr_constraint_add_match(cons, name)) {
    tr_debug("tr_cfg_default_filters: could not add wildcard realm name for domain constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  name=NULL;
  fline->domain_cons=cons;


  /* realm constraint */
  if (NULL==(cons=tr_constraint_new(fline))) {
    tr_debug("tr_cfg_default_filters: could not allocate realm constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  cons->type=n_realm;
  n_realm=NULL; /* belongs to the constraint now */
  name=tr_dup_name(realm);
  if (name==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate realm name for realm constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  if (NULL == tr_constraint_add_match(cons, name)) {
    tr_debug("tr_cfg_default_filters: could not add realm name for realm constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  name=tr_name_cat(n_prefix, realm);
  if (name==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate wildcard realm name for realm constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  if (NULL == tr_constraint_add_match(cons, name)) {
    tr_debug("tr_cfg_default_filters: could not add wildcard realm name for realm constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  name=NULL;
  fline->realm_cons=cons;

  /* put the fline in the filter */
  if (NULL == tr_filter_add_line(filt, fline)) {
    tr_debug("tr_cfg_default_filters: could not add line to filter.");
    *rc = TR_CFG_NOMEM;
    goto cleanup;
  }

  /* put the filter in a set */
  filt_set=tr_filter_set_new(tmp_ctx);
  if ((filt_set==NULL)||(0!=tr_filter_set_add(filt_set, filt))) {
    tr_debug("tr_cfg_default_filters: could not allocate filter set.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  talloc_steal(mem_ctx, filt_set);

cleanup:
  talloc_free(tmp_ctx);

  if (*rc!=TR_CFG_SUCCESS)
    filt=NULL;

  if (n_prefix!=NULL)
    tr_free_name(n_prefix);
  if (n_rp_realm_1!=NULL)
    tr_free_name(n_rp_realm_1);
  if (n_rp_realm_2!=NULL)
    tr_free_name(n_rp_realm_2);
  if (n_realm!=NULL)
    tr_free_name(n_realm);
  if (n_domain!=NULL)
    tr_free_name(n_domain);
  if (name!=NULL)
    tr_free_name(name);

  return filt_set;
}

/* parses rp client */
static TR_RP_CLIENT *tr_cfg_parse_one_rp_client(TALLOC_CTX *mem_ctx, json_t *jrealm, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_RP_CLIENT *client=NULL;
  TR_CFG_RC call_rc=TR_CFG_ERROR;
  TR_FILTER_SET *new_filts=NULL;
  TR_NAME *realm=NULL;
  json_t *jfilt=NULL;
  json_t *jrealm_id=NULL;

  *rc=TR_CFG_ERROR; /* default to error if not set */

  if ((!jrealm) || (!rc)) {
    tr_err("tr_cfg_parse_one_rp_client: Bad parameters.");
    if (rc)
      *rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  if ((NULL==(jrealm_id=json_object_get(jrealm, "realm"))) || (!json_is_string(jrealm_id))) {
    tr_debug("tr_cfg_parse_one_rp_client: no realm ID found.");
    *rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  tr_debug("tr_cfg_parse_one_rp_client: realm_id=\"%s\"", json_string_value(jrealm_id));
  realm=tr_new_name(json_string_value(jrealm_id));
  if (realm==NULL) {
    tr_err("tr_cfg_parse_one_rp_client: could not allocate realm ID.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  if (NULL==(client=tr_rp_client_new(tmp_ctx))) {
    tr_err("tr_cfg_parse_one_rp_client: could not allocate rp client.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  call_rc = tr_cfg_parse_gss_names(client, json_object_get(jrealm, "gss_names"), &(client->gss_names));

  if (call_rc!=TR_CFG_SUCCESS) {
    tr_err("tr_cfg_parse_one_rp_client: could not parse gss_names.");
    *rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  /* parse filters */
  jfilt=json_object_get(jrealm, "filters");
  if (jfilt!=NULL) {
    new_filts=tr_cfg_parse_filters(tmp_ctx, jfilt, &call_rc);
    if (call_rc!=TR_CFG_SUCCESS) {
      tr_err("tr_cfg_parse_one_rp_client: could not parse filters.");
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    }
  } else {
    tr_debug("tr_cfg_parse_one_rp_client: no filters specified, using default filters.");
    new_filts= tr_cfg_default_filters(tmp_ctx, realm, &call_rc);
    if (call_rc!=TR_CFG_SUCCESS) {
      tr_err("tr_cfg_parse_one_rp_client: could not set default filters.");
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    }
  }

  tr_rp_client_set_filters(client, new_filts);
  *rc=TR_CFG_SUCCESS;

cleanup:
  if (realm!=NULL)
    tr_free_name(realm);

  if (*rc==TR_CFG_SUCCESS)
    talloc_steal(mem_ctx, client);
  else {
    talloc_free(client);
    client=NULL;
  }

  talloc_free(tmp_ctx);
  return client;
}

/* Determine whether the realm is an RP realm */
static int tr_cfg_is_rp_realm(json_t *jrealm)
{
  /* Check that we have a gss name. */
  if (NULL != json_object_get(jrealm, "gss_names"))
    return 1;
  else
    return 0;
}

/* Parse any rp clients in the j_realms object. Ignores other realms. */
TR_RP_CLIENT *tr_cfg_parse_rp_clients(TALLOC_CTX *mem_ctx, json_t *jrealms, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_RP_CLIENT *clients=NULL;
  TR_RP_CLIENT *new_client=NULL;
  json_t *this_jrealm=NULL;
  int ii=0;

  *rc=TR_CFG_ERROR;
  if ((jrealms==NULL) || (!json_is_array(jrealms))) {
    tr_err("tr_cfg_parse_rp_clients: realms not an array");
    *rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  for (ii=0; ii<json_array_size(jrealms); ii++) {
    this_jrealm=json_array_get(jrealms, ii);
    if (tr_cfg_is_rp_realm(this_jrealm)) {
      new_client=tr_cfg_parse_one_rp_client(tmp_ctx, this_jrealm, rc);
      if ((*rc)!=TR_CFG_SUCCESS) {
        tr_err("tr_cfg_parse_rp_clients: error decoding realm entry %d", ii+1);
        *rc=TR_CFG_NOPARSE;
        goto cleanup;
      }
      tr_rp_client_add(clients, new_client);
    }
  }

  *rc=TR_CFG_SUCCESS;
  talloc_steal(mem_ctx, clients);

cleanup:
  talloc_free(tmp_ctx);
  return clients;
}
