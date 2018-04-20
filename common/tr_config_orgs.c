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

/* takes a talloc context, but currently does not use it */
static TR_NAME *tr_cfg_parse_org_name(TALLOC_CTX *mem_ctx, json_t *j_org, TR_CFG_RC *rc)
{
  TR_NAME *name=NULL;

  if ((j_org==NULL) || (rc==NULL) || (!json_is_string(j_org))) {
    tr_debug("tr_cfg_parse_org_name: Bad parameters.");
    if (rc!=NULL)
      *rc = TR_CFG_BAD_PARAMS; /* fill in return value if we can */
    return NULL;
  }

  name=tr_new_name(json_string_value(j_org));
  if (name==NULL)
    *rc=TR_CFG_NOMEM;
  else
    *rc=TR_CFG_SUCCESS;
  return name;
}

static TR_CFG_RC tr_cfg_parse_one_local_org(TR_CFG *trc, json_t *jlorg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_CFG_RC retval=TR_CFG_ERROR; /* our return code */
  TR_CFG_RC rc=TR_CFG_ERROR; /* return code from functions we call */
  TR_NAME *org_name=NULL;
  json_t *j_org=NULL;
  json_t *j_realms=NULL;
  TR_IDP_REALM *new_idp_realms=NULL;
  TR_RP_CLIENT *new_rp_clients=NULL;

  tr_debug("tr_cfg_parse_one_local_org: parsing local organization");

  /* get organization_name (optional) */
  if (NULL==(j_org=json_object_get(jlorg, "organization_name"))) {
    tr_debug("tr_cfg_parse_one_local_org: organization_name unspecified");
  } else {
    org_name=tr_cfg_parse_org_name(tmp_ctx, j_org, &rc);
    if (rc==TR_CFG_SUCCESS) {
      tr_debug("tr_cfg_parse_one_local_org: organization_name=\"%.*s\"",
               org_name->len,
               org_name->buf);
      /* we don't actually do anything with this, but we could */
      tr_free_name(org_name);
      org_name=NULL;
    }
  }

  /* Now get realms. Allow this to be missing; even though that is a pointless organization entry,
   * it's harmless. Report a warning because that might be unintentional. */
  if (NULL==(j_realms=json_object_get(jlorg, "realms"))) {
    tr_warning("tr_cfg_parse_one_local_org: warning - no realms in this local organization");
  } else {
    /* Allocate in the tmp_ctx so these will be cleaned up if we do not complete successfully. */
    new_idp_realms=tr_cfg_parse_idp_realms(tmp_ctx, j_realms, &rc);
    if (rc!=TR_CFG_SUCCESS)
      goto cleanup;

    new_rp_clients=tr_cfg_parse_rp_clients(tmp_ctx, j_realms, &rc);
    if (rc!=TR_CFG_SUCCESS)
      goto cleanup;
  }
  retval=TR_CFG_SUCCESS;

cleanup:
  /* if we succeeded, link things to the configuration and move out of tmp context */
  if (retval==TR_CFG_SUCCESS) {
    if (new_idp_realms!=NULL) {
      tr_idp_realm_add(trc->ctable->idp_realms, new_idp_realms); /* fixes talloc contexts except for head*/
      talloc_steal(trc, trc->ctable->idp_realms); /* make sure the head is in the right context */
    }

    if (new_rp_clients!=NULL) {
      tr_rp_client_add(trc->rp_clients, new_rp_clients); /* fixes talloc contexts */
      talloc_steal(trc, trc->rp_clients); /* make sure head is in the right context */
    }
  }

  talloc_free(tmp_ctx);
  return rc;
}

/* Parse local organizations if present. Returns success if there are none. On failure, the configuration is unreliable. */
TR_CFG_RC tr_cfg_parse_local_orgs(TR_CFG *trc, json_t *jcfg)
{
  json_t *jlocorgs=NULL;
  size_t ii=0;

  jlocorgs=json_object_get(jcfg, "local_organizations");
  if (jlocorgs==NULL)
    return TR_CFG_SUCCESS;

  if (!json_is_array(jlocorgs)) {
    tr_err("tr_cfg_parse_local_orgs: local_organizations is not an array.");
    return TR_CFG_NOPARSE;
  }

  for (ii=0; ii<json_array_size(jlocorgs); ii++) {
    if (tr_cfg_parse_one_local_org(trc, json_array_get(jlocorgs, ii))!=TR_CFG_SUCCESS) {
      tr_err("tr_cfg_parse_local_orgs: error parsing local_organization %d.", ii+1);
      return TR_CFG_NOPARSE;
    }
  }

  return TR_CFG_SUCCESS;
}

static TR_CFG_RC tr_cfg_parse_one_peer_org(TR_CFG *trc, json_t *jporg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  json_t *jhost=NULL;
  json_t *jport=NULL;
  json_t *jgss=NULL;
  json_t *jfilt=NULL;
  TRP_PEER *new_peer=NULL;
  TR_GSS_NAMES *names=NULL;
  TR_FILTER_SET *filt_set=NULL;
  TR_CFG_RC rc=TR_CFG_ERROR;

  jhost=json_object_get(jporg, "hostname");
  jport=json_object_get(jporg, "port");
  jgss=json_object_get(jporg, "gss_names");
  jfilt=json_object_get(jporg, "filters");

  if ((jhost==NULL) || (!json_is_string(jhost))) {
    tr_err("tr_cfg_parse_one_peer_org: hostname not specified or not a string.");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  if ((jport!=NULL) && (!json_is_number(jport))) {
    /* note that not specifying the port is allowed, but if set it must be a number */
    tr_err("tr_cfg_parse_one_peer_org: port is not a number.");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  if ((jgss==NULL) || (!json_is_array(jgss))) {
    tr_err("tr_cfg_parse_one_peer_org: gss_names not specified or not an array.");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  if ((jfilt!=NULL) && (!json_is_object(jfilt))) {
    tr_err("tr_cfg_parse_one_peer_org: filters is not an object.");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  new_peer=trp_peer_new(tmp_ctx);
  if (new_peer==NULL) {
    tr_err("tr_cfg_parse_one_peer_org: could not allocate new peer.");
    rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  trp_peer_set_server(new_peer, json_string_value(jhost)); /* string is strdup'ed in _set_server() */
  if (jport==NULL)
    trp_peer_set_port(new_peer, TRP_PORT);
  else
    trp_peer_set_port(new_peer, json_integer_value(jport));

  names=tr_cfg_parse_gss_names(tmp_ctx, jgss, &rc);
  if (rc!=TR_CFG_SUCCESS) {
    tr_err("tr_cfg_parse_one_peer_org: unable to parse gss names.");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }
  trp_peer_set_gss_names(new_peer, names);

  if (jfilt) {
    filt_set=tr_cfg_parse_filters(tmp_ctx, jfilt, &rc);
    if (rc!=TR_CFG_SUCCESS) {
      tr_err("tr_cfg_parse_one_peer_org: unable to parse filters.");
      rc=TR_CFG_NOPARSE;
      goto cleanup;
    }
    trp_peer_set_filters(new_peer, filt_set);
  }

  /* success! */
  trp_ptable_add(trc->peers, new_peer);
  rc=TR_CFG_SUCCESS;

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

/* Parse peer organizations, if present. Returns success if there are none. */
TR_CFG_RC tr_cfg_parse_peer_orgs(TR_CFG *trc, json_t *jcfg)
{
  json_t *jpeerorgs=NULL;
  int ii=0;

  jpeerorgs=json_object_get(jcfg, "peer_organizations");
  if (jpeerorgs==NULL)
    return TR_CFG_SUCCESS;

  if (!json_is_array(jpeerorgs)) {
    tr_err("tr_cfg_parse_peer_orgs: peer_organizations is not an array.");
    return TR_CFG_NOPARSE;
  }

  for (ii=0; ii<json_array_size(jpeerorgs); ii++) {
    if (tr_cfg_parse_one_peer_org(trc, json_array_get(jpeerorgs, ii))!=TR_CFG_SUCCESS) {
      tr_err("tr_cfg_parse_peer_orgs: error parsing peer_organization %d.", ii+1);
      return TR_CFG_NOPARSE;
    }
  }

  return TR_CFG_SUCCESS;
}

