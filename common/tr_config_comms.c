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

TR_CFG_RC tr_cfg_parse_default_servers (TR_CFG *trc, json_t *jcfg)
{
  json_t *jdss = NULL;
  TR_CFG_RC rc = TR_CFG_SUCCESS;
  TR_AAA_SERVER *ds = NULL;
  int i = 0;

  if ((!trc) || (!jcfg))
    return TR_CFG_BAD_PARAMS;

  /* If there are default servers, store them */
  if ((NULL != (jdss = json_object_get(jcfg, "default_servers"))) &&
      (json_is_array(jdss)) &&
      (0 < json_array_size(jdss))) {

    for (i = 0; i < json_array_size(jdss); i++) {
      if (NULL == (ds = tr_cfg_parse_one_aaa_server(trc,
                                                    json_array_get(jdss, i),
                                                   &rc))) {
	return rc;
      }
      tr_debug("tr_cfg_parse_default_servers: Default server configured: %s", ds->hostname->buf);
      ds->next = trc->default_servers;
      trc->default_servers = ds;
    }
  }

  tr_debug("tr_cfg_parse_default_servers: Finished (rc=%d)", rc);
  return rc;
}

static void tr_cfg_parse_comm_idps(TR_CFG *trc, json_t *jidps, TR_COMM *comm, TR_CFG_RC *rc)
{
  TR_IDP_REALM *found_idp=NULL;
  json_t *jidp_name=NULL;
  TR_NAME *idp_name=NULL;
  size_t ii = 0;

  if ((!trc) ||
      (!jidps) ||
      (!json_is_array(jidps))) {
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return;
  }

  json_array_foreach(jidps, ii, jidp_name) {
    idp_name=tr_new_name(json_string_value(jidp_name));
    if (idp_name==NULL) {
      *rc = TR_CFG_NOMEM;
      return;
    }
    found_idp=tr_cfg_find_idp(trc, idp_name, rc);
    tr_free_name(idp_name);

    if ((found_idp==NULL) || (*rc!=TR_CFG_SUCCESS)) {
      tr_debug("tr_cfg_parse_comm_idps: Unknown IDP %s.", json_string_value(jidp_name));
      *rc=TR_CFG_ERROR;
      return;
    }
    tr_comm_add_idp_realm(trc->ctable, comm, found_idp, 0, NULL, NULL); /* no provenance, never expires */
  }

  *rc=TR_CFG_SUCCESS;
  return;
}

static void tr_cfg_parse_comm_rps(TR_CFG *trc, json_t *jrps, TR_COMM *comm, TR_CFG_RC *rc)
{
  TR_RP_REALM *found_rp=NULL;
  TR_RP_REALM *new_rp=NULL;
  TR_NAME *rp_name=NULL;
  const char *s=NULL;
  int ii=0;

  if ((!trc) ||
      (!jrps) ||
      (!json_is_array(jrps))) {
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return;
  }

  for (ii=0; ii<json_array_size(jrps); ii++) {
    /* get the RP name as a string */
    s=json_string_value(json_array_get(jrps, ii));
    if (s==NULL) {
      tr_notice("tr_cfg_parse_comm_rps: null RP found in community %.*s, ignoring.",
                tr_comm_get_id(comm)->len, tr_comm_get_id(comm)->buf);
      continue;
    }

    /* convert string to TR_NAME */
    rp_name=tr_new_name(s);
    if (rp_name==NULL) {
      tr_err("tr_cfg_parse_comm_rps: unable to allocate RP name for %s in community %.*s.",
             s, tr_comm_get_id(comm)->len, tr_comm_get_id(comm)->buf);
      continue;
    }

    /* see if we already have this RP in this community */
    found_rp=tr_comm_find_rp(trc->ctable, comm, rp_name);
    if (found_rp!=NULL) {
      tr_notice("tr_cfg_parse_comm_rps: RP %s repeated in community %.*s.",
                s, tr_comm_get_id(comm)->len, tr_comm_get_id(comm)->buf);
      tr_free_name(rp_name);
      continue;
    }

    /* Add the RP to the community, first see if we have the RP in any community */
    found_rp=tr_rp_realm_lookup(trc->ctable->rp_realms, rp_name);
    if (found_rp!=NULL) {
      tr_debug("tr_cfg_parse_comm_rps: RP realm %s already exists.", s);
      new_rp=found_rp; /* use it rather than creating a new realm record */
    } else {
      new_rp=tr_rp_realm_new(NULL);
      if (new_rp==NULL) {
        tr_err("tr_cfg_parse_comm_rps: unable to allocate RP record for %s in community %.*s.",
               s, tr_comm_get_id(comm)->len, tr_comm_get_id(comm)->buf);
      }
      tr_debug("tr_cfg_parse_comm_rps: setting name to %s", rp_name->buf);
      tr_rp_realm_set_id(new_rp, rp_name);
      rp_name=NULL; /* rp_name no longer belongs to us */
      tr_rp_realm_add(trc->ctable->rp_realms, new_rp);
      talloc_steal(trc->ctable, trc->ctable->rp_realms); /* make sure head is in the right context */
    }
    tr_comm_add_rp_realm(trc->ctable, comm, new_rp, 0, NULL, NULL);
  }
}

static TR_COMM *tr_cfg_parse_one_comm (TALLOC_CTX *mem_ctx, TR_CFG *trc, json_t *jcomm, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM *comm = NULL;
  json_t *jid = NULL;
  json_t *jtype = NULL;
  json_t *japcs = NULL;
  json_t *jidps = NULL;
  json_t *jrps = NULL;

  if ((!trc) || (!jcomm) || (!rc)) {
    tr_debug("tr_cfg_parse_one_comm: Bad parameters.");
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  comm=tr_comm_new(tmp_ctx);
  if (comm==NULL) {
    tr_crit("tr_cfg_parse_one_comm: Out of memory.");
    *rc = TR_CFG_NOMEM;
    goto cleanup;
  }


  if ((NULL == (jid = json_object_get(jcomm, "community_id"))) ||
      (!json_is_string(jid)) ||
      (NULL == (jtype = json_object_get(jcomm, "type"))) ||
      (!json_is_string(jtype)) ||
      (NULL == (japcs = json_object_get(jcomm, "apcs"))) ||
      (!json_is_array(japcs)) ||
      (NULL == (jidps = json_object_get(jcomm, "idp_realms"))) ||
      (!json_is_array(jidps)) ||
      (NULL == (jrps = json_object_get(jcomm, "rp_realms"))) ||
      (!json_is_array(jrps))) {
    tr_debug("tr_cfg_parse_one_comm: Error parsing Communities configuration.");
    *rc = TR_CFG_NOPARSE;
    comm=NULL;
    goto cleanup;
  }

  tr_comm_set_id(comm, tr_new_name(json_string_value(jid)));
  if (NULL == tr_comm_get_id(comm)) {
    tr_debug("tr_cfg_parse_one_comm: No memory for community id.");
    *rc = TR_CFG_NOMEM;
    comm=NULL;
    goto cleanup;
  }

  if (0 == strcmp(json_string_value(jtype), "apc")) {
    comm->type = TR_COMM_APC;
  } else if (0 == strcmp(json_string_value(jtype), "coi")) {
    comm->type = TR_COMM_COI;
    if (NULL == (comm->apcs = tr_cfg_parse_apcs(trc, japcs, rc))) {
      tr_debug("tr_cfg_parse_one_comm: Can't parse APCs for COI %s.",
               tr_comm_get_id(comm)->buf);
      comm=NULL;
      goto cleanup;
    }
  } else {
    tr_debug("tr_cfg_parse_one_comm: Invalid community type, comm = %s, type = %s",
             tr_comm_get_id(comm)->buf, json_string_value(jtype));
    *rc = TR_CFG_NOPARSE;
    comm=NULL;
    goto cleanup;
  }

  tr_cfg_parse_comm_idps(trc, jidps, comm, rc);
  if (TR_CFG_SUCCESS != *rc) {
    tr_debug("tr_cfg_parse_one_comm: Can't parse IDP realms for comm %s.",
             tr_comm_get_id(comm)->buf);
    comm=NULL;
    goto cleanup;
  }

  tr_cfg_parse_comm_rps(trc, jrps, comm, rc);
  if (TR_CFG_SUCCESS != *rc) {
    tr_debug("tr_cfg_parse_one_comm: Can't parse RP realms for comm %s .",
             tr_comm_get_id(comm)->buf);
    comm=NULL;
    goto cleanup;
  }

  if (TR_COMM_APC == comm->type) {
    json_t *jexpire  = json_object_get(jcomm, "expiration_interval");
    comm->expiration_interval = 43200; /*30 days*/
    if (jexpire) {
      if (!json_is_integer(jexpire)) {
        tr_err("tr_parse_one_comm: expiration_interval is not an integer for comm %.*s",
                 tr_comm_get_id(comm)->len, tr_comm_get_id(comm)->buf);
        comm=NULL;
        goto cleanup;
      }
      comm->expiration_interval = json_integer_value(jexpire);
      if (comm->expiration_interval <= 10) {
        comm->expiration_interval = 11; /* Freeradius waits 10 minutes between successful TR queries*/
        tr_notice(
            "tr_parse_one_comm: expiration interval for %.*s less than minimum of 11 minutes; using 11 minutes instead.",
            tr_comm_get_id(comm)->len, tr_comm_get_id(comm)->buf);
      }
      if (comm->expiration_interval > 129600) {
        /* > 90 days*/
        comm->expiration_interval = 129600;
        tr_notice(
            "tr_parse_one_comm: expiration interval for %.*s exceeds maximum of 90 days; using 90 days instead.",
            tr_comm_get_id(comm)->len, tr_comm_get_id(comm)->buf);
      }
    }
  }

cleanup:
  if (comm!=NULL)
    talloc_steal(mem_ctx, comm);
  talloc_free(tmp_ctx);
  return comm;
}

TR_CFG_RC tr_cfg_parse_comms (TR_CFG *trc, json_t *jcfg)
{
  json_t *jcomms = NULL;
  TR_CFG_RC rc = TR_CFG_SUCCESS;
  TR_COMM *comm = NULL;
  int i = 0;

  if ((!trc) || (!jcfg)) {
    tr_debug("tr_cfg_parse_comms: Bad Parameters.");
    return TR_CFG_BAD_PARAMS;
  }

  if (NULL != (jcomms = json_object_get(jcfg, "communities"))) {
    if (!json_is_array(jcomms)) {
      return TR_CFG_NOPARSE;
    }

    for (i = 0; i < json_array_size(jcomms); i++) {
      if (NULL == (comm = tr_cfg_parse_one_comm(NULL, /* TODO: use a talloc context */
                                                trc,
                                                json_array_get(jcomms, i),
                                               &rc))) {
        return rc;
      }
      if (tr_comm_table_add_comm(trc->ctable, comm) != 0) {
        tr_debug("tr_cfg_parse_comms: Duplicate community %s.", tr_comm_get_id(comm)->buf);
        return TR_CFG_NOPARSE;
      }

      tr_debug("tr_cfg_parse_comms: Community configured: %s.",
               tr_comm_get_id(comm)->buf);
    }
  }
  tr_debug("tr_cfg_parse_comms: Finished (rc=%d)", rc);
  return rc;
}

TR_IDP_REALM *tr_cfg_find_idp (TR_CFG *tr_cfg, TR_NAME *idp_id, TR_CFG_RC *rc)
{

  TR_IDP_REALM *cfg_idp;

  if ((!tr_cfg) || (!idp_id)) {
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  for (cfg_idp = tr_cfg->ctable->idp_realms; NULL != cfg_idp; cfg_idp = cfg_idp->next) {
    if (!tr_name_cmp (idp_id, cfg_idp->realm_id)) {
      tr_debug("tr_cfg_find_idp: Found %s.", idp_id->buf);
      return cfg_idp;
    }
  }
  /* if we didn't find one, return NULL */
  return NULL;
}

TR_RP_CLIENT *tr_cfg_find_rp (TR_CFG *tr_cfg, TR_NAME *rp_gss, TR_CFG_RC *rc)
{
  TR_RP_CLIENT *cfg_rp;

  if ((!tr_cfg) || (!rp_gss)) {
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  for (cfg_rp = tr_cfg->rp_clients; NULL != cfg_rp; cfg_rp = cfg_rp->next) {
    if (tr_gss_names_matches(cfg_rp->gss_names, rp_gss)) {
      tr_debug("tr_cfg_find_rp: Found %s.", rp_gss->buf);
      return cfg_rp;
    }
  }
  /* if we didn't find one, return NULL */
  return NULL;
}
