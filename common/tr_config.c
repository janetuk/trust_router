/*
 * Copyright (c) 2012, JANET(UK)
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

void tr_print_config (TR_CFG *cfg) {
  tr_notice("tr_print_config: Logging running trust router configuration.");
  tr_print_comms(cfg->ctable);
}

void tr_print_comms (TR_COMM_TABLE *ctab)
{
  TR_COMM *comm = NULL;

  for (comm = ctab->comms; NULL != comm; comm = comm->next) {
    tr_notice("tr_print_config: Community %s:", comm->id->buf);

    tr_notice("tr_print_config:  - Member IdPs:");
    tr_print_comm_idps(ctab, comm);

    tr_notice("tr_print_config:  - Member RPs:");
    tr_print_comm_rps(ctab, comm);
  }
}

void tr_print_comm_idps(TR_COMM_TABLE *ctab, TR_COMM *comm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM_ITER *iter=NULL;
  TR_IDP_REALM *idp = NULL;
  char *s=NULL;

  iter=tr_comm_iter_new(tmp_ctx);
  if (iter==NULL) {
    tr_notice("tr_print_config: unable to allocate IdP iterator.");
    talloc_free(tmp_ctx);
    return;
  }
  
  for (idp=tr_idp_realm_iter_first(iter, ctab, tr_comm_get_id(comm));
       NULL!=idp;
       idp=tr_idp_realm_iter_next(iter)) {
    s=tr_idp_realm_to_str(tmp_ctx, idp);
    if (s!=NULL)
      tr_notice("tr_print_config:    - @%s", s);
    else
      tr_notice("tr_print_config: unable to allocate IdP output string.");
  }
  talloc_free(tmp_ctx);
}

void tr_print_comm_rps(TR_COMM_TABLE *ctab, TR_COMM *comm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM_ITER *iter=NULL;
  TR_RP_REALM *rp = NULL;
  char *s=NULL;

  iter=tr_comm_iter_new(tmp_ctx);
  if (iter==NULL) {
    tr_notice("tr_print_config: unable to allocate RP iterator.");
    talloc_free(tmp_ctx);
    return;
  }
  
  for (rp=tr_rp_realm_iter_first(iter, ctab, tr_comm_get_id(comm));
       NULL!=rp;
       rp=tr_rp_realm_iter_next(iter)) {
    s=tr_rp_realm_to_str(tmp_ctx, rp);
    if (s!=NULL)
      tr_notice("tr_print_config:    - @%s", s);
    else
      tr_notice("tr_print_config: unable to allocate RP output string.");
  }
  talloc_free(tmp_ctx);
}

TR_CFG *tr_cfg_new(TALLOC_CTX *mem_ctx)
{
  TR_CFG *cfg=talloc(mem_ctx, TR_CFG);
  if (cfg!=NULL) {
    cfg->internal=NULL;
    cfg->rp_clients=NULL;
    cfg->peers=NULL;
    cfg->default_servers=NULL;
    cfg->ctable=tr_comm_table_new(cfg);
    if (cfg->ctable==NULL) {
      talloc_free(cfg);
      cfg=NULL;
    }
  }
  return cfg;
}

void tr_cfg_free (TR_CFG *cfg)
{
  talloc_free(cfg);
}

TR_CFG_MGR *tr_cfg_mgr_new(TALLOC_CTX *mem_ctx)
{
  return talloc_zero(mem_ctx, TR_CFG_MGR);
}

void tr_cfg_mgr_free (TR_CFG_MGR *cfg_mgr) {
  talloc_free(cfg_mgr);
}

TR_CFG_RC tr_apply_new_config (TR_CFG_MGR *cfg_mgr)
{
  /* cfg_mgr->active is allowed to be null, but new cannot be */
  if ((cfg_mgr==NULL) || (cfg_mgr->new==NULL))
    return TR_CFG_BAD_PARAMS;

  if (cfg_mgr->active != NULL)
    tr_cfg_free(cfg_mgr->active);

  cfg_mgr->active = cfg_mgr->new;
  cfg_mgr->new=NULL; /* only keep a single handle on the new configuration */

  tr_log_threshold(cfg_mgr->active->internal->log_threshold);
  tr_console_threshold(cfg_mgr->active->internal->console_threshold);

  return TR_CFG_SUCCESS;
}

static TR_CONSTRAINT *tr_cfg_parse_one_constraint(TALLOC_CTX *mem_ctx, char *ctype, json_t *jc, TR_CFG_RC *rc)
{
  TR_CONSTRAINT *cons=NULL;
  int i=0;

  if ((!ctype) || (!jc) || (!rc) ||
      (!json_is_array(jc)) ||
      (0 >= json_array_size(jc)) ||
      (TR_MAX_CONST_MATCHES < json_array_size(jc)) ||
      (!json_is_string(json_array_get(jc, 0)))) {
    tr_err("tr_cfg_parse_one_constraint: config error.");
    *rc=TR_CFG_NOPARSE;
    return NULL;
  }

  if (NULL==(cons=tr_constraint_new(mem_ctx))) {
    tr_debug("tr_cfg_parse_one_constraint: Out of memory (cons).");
    *rc=TR_CFG_NOMEM;
    return NULL;
  }

  if (NULL==(cons->type=tr_new_name(ctype))) {
    tr_err("tr_cfg_parse_one_constraint: Out of memory (type).");
    *rc=TR_CFG_NOMEM;
    tr_constraint_free(cons);
    return NULL;
  }

  for (i=0; i < json_array_size(jc); i++) {
    cons->matches[i]=tr_new_name(json_string_value(json_array_get(jc, i)));
    if (cons->matches[i]==NULL) {
      tr_err("tr_cfg_parse_one_constraint: Out of memory (match %d).", i+1);
      *rc=TR_CFG_NOMEM;
      tr_constraint_free(cons);
      return NULL;
    }
  }

  return cons;
}

static TR_FILTER *tr_cfg_parse_one_filter(TALLOC_CTX *mem_ctx, json_t *jfilt, TR_FILTER_TYPE ftype, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  TR_FILTER *filt = NULL;
  json_t *jfaction = NULL;
  json_t *jfline = NULL;
  json_t *jfspecs = NULL;
  json_t *this_jfspec = NULL;
  json_t *jfield = NULL;
  json_t *jmatch = NULL;
  json_t *jrc = NULL;
  json_t *jdc = NULL;
  json_t *this_jmatch = NULL;
  TR_NAME *name = NULL;
  size_t i = 0, j = 0, k = 0;

  *rc = TR_CFG_ERROR;

  if ((jfilt == NULL) || (rc == NULL)) {
    tr_err("tr_cfg_parse_one_filter: null argument");
    *rc = TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  if (NULL == (filt = tr_filter_new(tmp_ctx))) {
    tr_err("tr_cfg_parse_one_filter: Out of memory.");
    *rc = TR_CFG_NOMEM;
    goto cleanup;
  }
  tr_filter_set_type(filt, ftype);

  /* make sure we have space to represent the filter */
  if (json_array_size(jfilt) > TR_MAX_FILTER_LINES) {
    tr_err("tr_cfg_parse_one_filter: Filter has too many lines, maximum of %d.", TR_MAX_FILTER_LINES);
    *rc = TR_CFG_NOPARSE;
    goto cleanup;
  }

  /* For each entry in the filter... */
  json_array_foreach(jfilt, i, jfline) {
    if ((NULL == (jfaction = json_object_get(jfline, "action"))) ||
        (!json_is_string(jfaction))) {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter action.");
      *rc = TR_CFG_NOPARSE;
      goto cleanup;
    }

    if ((NULL == (jfspecs = json_object_get(jfline, "specs"))) ||
        (!json_is_array(jfspecs)) ||
        (0 == json_array_size(jfspecs))) {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter specs.");
      *rc = TR_CFG_NOPARSE;
      goto cleanup;
    }

    if (TR_MAX_FILTER_SPECS < json_array_size(jfspecs)) {
      tr_debug("tr_cfg_parse_one_filter: Filter has too many specs, maximimum of %d.", TR_MAX_FILTER_SPECS);
      *rc = TR_CFG_NOPARSE;
      goto cleanup;
    }

    if (NULL == (filt->lines[i] = tr_fline_new(filt))) {
      tr_debug("tr_cfg_parse_one_filter: Out of memory allocating filter line %d.", i + 1);
      *rc = TR_CFG_NOMEM;
      goto cleanup;
    }

    if (!strcmp(json_string_value(jfaction), "accept")) {
      filt->lines[i]->action = TR_FILTER_ACTION_ACCEPT;
    } else if (!strcmp(json_string_value(jfaction), "reject")) {
      filt->lines[i]->action = TR_FILTER_ACTION_REJECT;
    } else {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter action, unknown action' %s'.",
               json_string_value(jfaction));
      *rc = TR_CFG_NOPARSE;
      goto cleanup;
    }

    if (NULL != (jrc = json_object_get(jfline, "realm_constraints"))) {
      if (!json_is_array(jrc)) {
        tr_err("tr_cfg_parse_one_filter: cannot parse realm_constraints, not an array.");
        *rc = TR_CFG_NOPARSE;
        goto cleanup;
      } else if (json_array_size(jrc) > TR_MAX_CONST_MATCHES) {
        tr_err("tr_cfg_parse_one_filter: realm_constraints has too many entries, maximum of %d.",
               TR_MAX_CONST_MATCHES);
        *rc = TR_CFG_NOPARSE;
        goto cleanup;
      } else if (json_array_size(jrc) > 0) {
        /* ok we actually have entries to process */
        if (NULL == (filt->lines[i]->realm_cons = tr_cfg_parse_one_constraint(filt->lines[i], "realm", jrc, rc))) {
          tr_debug("tr_cfg_parse_one_filter: Error parsing realm constraint");
          *rc = TR_CFG_NOPARSE;
          goto cleanup;
        }
      }
    }

    if (NULL != (jdc = json_object_get(jfline, "domain_constraints"))) {
      if (!json_is_array(jdc)) {
        tr_err("tr_cfg_parse_one_filter: cannot parse domain_constraints, not an array.");
        *rc = TR_CFG_NOPARSE;
        goto cleanup;
      } else if (json_array_size(jdc) > TR_MAX_CONST_MATCHES) {
        tr_err("tr_cfg_parse_one_filter: domain_constraints has too many entries, maximum of %d.",
               TR_MAX_CONST_MATCHES);
        *rc = TR_CFG_NOPARSE;
        goto cleanup;
      } else if (json_array_size(jdc) > 0) {
        if (NULL == (filt->lines[i]->domain_cons = tr_cfg_parse_one_constraint(filt->lines[i], "domain", jdc, rc))) {
          tr_debug("tr_cfg_parse_one_filter: Error parsing domain constraint");
          *rc = TR_CFG_NOPARSE;
          goto cleanup;
        }
      }
    }

    /*For each filter spec within the filter line... */
    json_array_foreach(jfspecs, j, this_jfspec) {
      if ((NULL == (jfield = json_object_get(this_jfspec, "field"))) ||
          (!json_is_string(jfield))) {
        tr_debug("tr_cfg_parse_one_filter: Error parsing filter: missing field for filer spec %d, filter line %d.", i,
                 j);
        *rc = TR_CFG_NOPARSE;
        goto cleanup;
      }

      /* check that we have a match attribute */
      if (NULL == (jmatch = json_object_get(this_jfspec, "match"))) {
        tr_debug("tr_cfg_parse_one_filter: Error parsing filter: missing match for filer spec %d, filter line %d.", i,
                 j);
        *rc = TR_CFG_NOPARSE;
        goto cleanup;
      }

      /* check that match is a string or an array */
      if ((!json_is_string(jmatch)) && (!json_is_array(jmatch))) {
        tr_debug(
            "tr_cfg_parse_one_filter: Error parsing filter: match not a string or array for filter spec %d, filter line %d.",
            i, j);
        *rc = TR_CFG_NOPARSE;
        goto cleanup;
      }

      /* allocate the filter spec */
      if (NULL == (filt->lines[i]->specs[j] = tr_fspec_new(filt->lines[i]))) {
        tr_debug("tr_cfg_parse_one_filter: Out of memory.");
        *rc = TR_CFG_NOMEM;
        goto cleanup;
      }

      /* fill in the field */
      if (NULL == (filt->lines[i]->specs[j]->field = tr_new_name(json_string_value(jfield)))) {
        tr_debug("tr_cfg_parse_one_filter: Out of memory.");
        *rc = TR_CFG_NOMEM;
        goto cleanup;
      }

      /* fill in the matches */
      if (json_is_string(jmatch)) {
        if (NULL == (name = tr_new_name(json_string_value(jmatch)))) {
          tr_debug("tr_cfg_parse_one_filter: Out of memory.");
          *rc = TR_CFG_NOMEM;
          goto cleanup;
        }
        tr_fspec_add_match(filt->lines[i]->specs[j], name);
      } else {
        /* jmatch is an array (we checked earlier) */
        json_array_foreach(jmatch, k, this_jmatch) {
          if (NULL == (name = tr_new_name(json_string_value(this_jmatch)))) {
            tr_debug("tr_cfg_parse_one_filter: Out of memory.");
            *rc = TR_CFG_NOMEM;
            goto cleanup;
          }
          tr_fspec_add_match(filt->lines[i]->specs[j], name);
        }
      }
      if (!tr_filter_validate_spec_field(ftype, filt->lines[i]->specs[j])){
        tr_debug("tr_cfg_parse_one_filter: Invalid filter field \"%.*s\" for %s filter, spec %d, filter %d.",
                 filt->lines[i]->specs[j]->field->len,
                 filt->lines[i]->specs[j]->field->buf,
                 tr_filter_type_to_string(filt->type),
                 i, j);
        *rc = TR_CFG_ERROR;
        goto cleanup;
      }
    }
  }

  /* check that the filter is valid */
  if (!tr_filter_validate(filt)) {
    *rc = TR_CFG_ERROR;
  } else {
    *rc = TR_CFG_SUCCESS;
    talloc_steal(mem_ctx, filt);
  }

 cleanup:
  talloc_free(tmp_ctx);
  if (*rc!=TR_CFG_SUCCESS)
    filt=NULL;
  return filt;
}

static TR_FILTER_SET *tr_cfg_parse_filters(TALLOC_CTX *mem_ctx, json_t *jfilts, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  json_t *jfilt;
  const char *filt_label=NULL;
  TR_FILTER *filt=NULL;
  TR_FILTER_SET *filt_set=NULL;
  TR_FILTER_TYPE filt_type=TR_FILTER_TYPE_UNKNOWN;

  *rc=TR_CFG_ERROR;

  /* no filters */
  if (jfilts==NULL) {
    *rc=TR_CFG_SUCCESS;
    goto cleanup;
  }

  filt_set=tr_filter_set_new(tmp_ctx);
  if (filt_set==NULL) {
    tr_debug("tr_cfg_parse_filters: Unable to allocate filter set.");
    *rc = TR_CFG_NOMEM;
    goto cleanup;
  }

  json_object_foreach(jfilts, filt_label, jfilt) {
    /* check that we got a filter */
    if (jfilt == NULL) {
      tr_debug("tr_cfg_parse_filters: Definition for %s filter is missing.", filt_label);
      *rc = TR_CFG_NOPARSE;
      goto cleanup;
    }

    /* check that we recognize the filter type */
    filt_type=tr_filter_type_from_string(filt_label);
    if (filt_type==TR_FILTER_TYPE_UNKNOWN) {
      tr_debug("tr_cfg_parse_filters: Unrecognized filter (%s) defined.", filt_label);
      *rc = TR_CFG_NOPARSE;
      goto cleanup;
    }

    /* finally, parse the filter */
    tr_debug("tr_cfg_parse_filters: Found %s filter.", filt_label);
    filt = tr_cfg_parse_one_filter(tmp_ctx, jfilt, filt_type, rc);
    tr_filter_set_add(filt_set, filt);
    if (*rc != TR_CFG_SUCCESS) {
      tr_debug("tr_cfg_parse_filters: Error parsing %s filter.", filt_label);
      *rc = TR_CFG_NOPARSE;
      goto cleanup;
    }
  }

  *rc=TR_CFG_SUCCESS;

 cleanup:
  if (*rc==TR_CFG_SUCCESS)
    talloc_steal(mem_ctx, filt_set);
  else if (filt_set!=NULL) {
    talloc_free(filt_set);
    filt_set=NULL;
  }

  talloc_free(tmp_ctx);
  return filt_set;
}

static TR_AAA_SERVER *tr_cfg_parse_one_aaa_server(TALLOC_CTX *mem_ctx, json_t *jaddr, TR_CFG_RC *rc)
{
  TR_AAA_SERVER *aaa = NULL;
  TR_NAME *name=NULL;

  if ((!jaddr) || (!json_is_string(jaddr))) {
    tr_debug("tr_cfg_parse_one_aaa_server: Bad parameters.");
    *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  name=tr_new_name(json_string_value(jaddr));
  if (name==NULL) {
    tr_debug("tr_cfg_parse_one_aaa_server: Out of memory allocating hostname.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  aaa=tr_aaa_server_new(mem_ctx, name);
  if (aaa==NULL) {
    tr_free_name(name);
    tr_debug("tr_cfg_parse_one_aaa_server: Out of memory allocating AAA server.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

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

static TR_APC *tr_cfg_parse_apcs(TALLOC_CTX *mem_ctx, json_t *japcs, TR_CFG_RC *rc)
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
static TR_IDP_REALM *tr_cfg_parse_idp_realms(TALLOC_CTX *mem_ctx, json_t *jrealms, TR_CFG_RC *rc)
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

static TR_GSS_NAMES *tr_cfg_parse_gss_names(TALLOC_CTX *mem_ctx, json_t *jgss_names, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_GSS_NAMES *gn=NULL;
  json_t *jname=NULL;
  int ii=0;
  TR_NAME *name=NULL;

  if ((rc==NULL) || (jgss_names==NULL)) {
    tr_err("tr_cfg_parse_gss_names: Bad parameters.");
    *rc=TR_CFG_BAD_PARAMS;

  }

  if (!json_is_array(jgss_names)) {
    tr_err("tr_cfg_parse_gss_names: gss_names not an array.");
    *rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  gn=tr_gss_names_new(tmp_ctx);
  for (ii=0; ii<json_array_size(jgss_names); ii++) {
    jname=json_array_get(jgss_names, ii);
    if (!json_is_string(jname)) {
      tr_err("tr_cfg_parse_gss_names: Encountered non-string gss name.");
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    }

    name=tr_new_name(json_string_value(jname));
    if (name==NULL) {
      tr_err("tr_cfg_parse_gss_names: Out of memory allocating gss name.");
      *rc=TR_CFG_NOMEM;
      goto cleanup;
    }

    if (tr_gss_names_add(gn, name)!=0) {
      tr_free_name(name);
      tr_err("tr_cfg_parse_gss_names: Unable to add gss name to RP client.");
      *rc=TR_CFG_ERROR;
      goto cleanup;
    }
  }

  talloc_steal(mem_ctx, gn);
  *rc=TR_CFG_SUCCESS;

 cleanup:
  talloc_free(tmp_ctx);
  if ((*rc!=TR_CFG_SUCCESS) && (gn!=NULL))
    gn=NULL;
  return gn;
}

/* default filter accepts realm and *.realm */
static TR_FILTER_SET *tr_cfg_default_filters(TALLOC_CTX *mem_ctx, TR_NAME *realm, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_FILTER *filt=NULL;
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
  filt->lines[0]=tr_fline_new(filt);
  if (filt->lines[0]==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate filter line.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  filt->lines[0]->action=TR_FILTER_ACTION_ACCEPT;
  filt->lines[0]->specs[0]=tr_fspec_new(filt->lines[0]);
  filt->lines[0]->specs[0]->field=n_rp_realm_1;
  n_rp_realm_1=NULL; /* we don't own this name any more */

  name=tr_dup_name(realm);
  if (name==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate realm name.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  tr_fspec_add_match(filt->lines[0]->specs[0], name);
  name=NULL; /* we no longer own the name */

  /* now do the wildcard name */
  filt->lines[0]->specs[1]=tr_fspec_new(filt->lines[0]);
  filt->lines[0]->specs[1]->field=n_rp_realm_2;
  n_rp_realm_2=NULL; /* we don't own this name any more */

  if (NULL==(name=tr_name_cat(n_prefix, realm))) {
    tr_debug("tr_cfg_default_filters: could not allocate wildcard realm name.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  tr_fspec_add_match(filt->lines[0]->specs[1], name);
  name=NULL; /* we no longer own the name */

  /* domain constraint */
  if (NULL==(cons=tr_constraint_new(filt->lines[0]))) {
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
  cons->matches[0]=name;
  name=tr_name_cat(n_prefix, realm);
  if (name==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate wildcard realm name for domain constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  cons->matches[1]=name;
  name=NULL;
  filt->lines[0]->domain_cons=cons;


  /* realm constraint */
  if (NULL==(cons=tr_constraint_new(filt->lines[0]))) {
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
  cons->matches[0]=name;
  name=tr_name_cat(n_prefix, realm);
  if (name==NULL) {
    tr_debug("tr_cfg_default_filters: could not allocate wildcard realm name for realm constraint.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  cons->matches[1]=name;
  name=NULL;
  filt->lines[0]->realm_cons=cons;

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

  client->gss_names=tr_cfg_parse_gss_names(client, json_object_get(jrealm, "gss_names"), &call_rc);

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
static TR_RP_CLIENT *tr_cfg_parse_rp_clients(TALLOC_CTX *mem_ctx, json_t *jrealms, TR_CFG_RC *rc)
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
static TR_CFG_RC tr_cfg_parse_local_orgs(TR_CFG *trc, json_t *jcfg)
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
static TR_CFG_RC tr_cfg_parse_peer_orgs(TR_CFG *trc, json_t *jcfg)
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
             
static TR_CFG_RC tr_cfg_parse_default_servers (TR_CFG *trc, json_t *jcfg) 
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

static TR_CFG_RC tr_cfg_parse_comms (TR_CFG *trc, json_t *jcfg) 
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
      tr_debug("tr_cfg_parse_comms: Community configured: %s.",
               tr_comm_get_id(comm)->buf);

      tr_comm_table_add_comm(trc->ctable, comm);
    }
  }
  tr_debug("tr_cfg_parse_comms: Finished (rc=%d)", rc);
  return rc;
}

TR_CFG_RC tr_cfg_validate(TR_CFG *trc)
{
  TR_CFG_RC rc = TR_CFG_SUCCESS;

  if (!trc)
    return TR_CFG_BAD_PARAMS;

  if ((NULL == trc->internal)||
      (NULL == trc->internal->hostname)) {
    tr_debug("tr_cfg_validate: Error: No internal configuration, or no hostname.");
    rc = TR_CFG_ERROR;
  }

  if (NULL == trc->rp_clients) {
    tr_debug("tr_cfg_validate: Error: No RP Clients configured");
    rc = TR_CFG_ERROR;
  }

  if (0==tr_comm_table_size(trc->ctable)) {
    tr_debug("tr_cfg_validate: Error: No Communities configured");
    rc = TR_CFG_ERROR;
  }

  if ((NULL == trc->default_servers) && (NULL == trc->ctable->idp_realms)) {
    tr_debug("tr_cfg_validate: Error: No default servers or IDPs configured.");
    rc = TR_CFG_ERROR;
  }
  
  return rc;
}

static void tr_cfg_log_json_error(const char *label, json_error_t *rc)
{
  tr_debug("%s: JSON parse error on line %d: %s",
	   label,
	   rc->line,
	   rc->text);
}

/**
 * Parse a config file and return its JSON structure. Also emits a serial number to the log
 * if one is present.
 *
 * @param file_with_path The file (with path!) to parse
 * @return Pointer to the result of parsing, or null on error
 */
static json_t *tr_cfg_parse_one_config_file(const char *file_with_path)
{
  json_t *jcfg=NULL;
  json_t *jser=NULL;
  json_error_t rc;

  if (NULL==(jcfg=json_load_file(file_with_path, 
                                 JSON_DISABLE_EOF_CHECK|JSON_REJECT_DUPLICATES, &rc))) {
    tr_debug("tr_cfg_parse_one_config_file: Error parsing config file %s.", 
             file_with_path);
    tr_cfg_log_json_error("tr_cfg_parse_one_config_file", &rc);
    return NULL;
  }

  // Look for serial number and log it if it exists (borrowed reference, so no need to free it later)
  if (NULL!=(jser=json_object_get(jcfg, "serial_number"))) {
    if (json_is_number(jser)) {
      tr_notice("tr_parse_one_config_file: Attempting to load revision %" JSON_INTEGER_FORMAT " of '%s'.",
                json_integer_value(jser),
                file_with_path);
    }
  }

  return jcfg;
}

/**
 * Helper to free an array returned by tr_cfg_parse_config_files
 * @param n_jcfgs
 * @param jcfgs
 */
static void tr_cfg_parse_free_jcfgs(unsigned int n_jcfgs, json_t **jcfgs)
{
  int ii=0;
  for (ii=0; ii<n_jcfgs; ii++)
    json_decref(jcfgs[ii]);
  talloc_free(jcfgs);
}

/**
 * Parse a list of configuration files. Returns an array of JSON objects, free this with
 * tr_cfg_parse_free_jcfgs(), a helper function
 *
 * @param config_dir
 * @param n_files
 * @param cfg_files
 * @return
 */
static json_t **tr_cfg_parse_config_files(TALLOC_CTX *mem_ctx, unsigned int n_files, char **files_with_paths)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  unsigned int ii=0;
  json_t **jcfgs=NULL;

  /* first allocate the jcfgs */
  jcfgs=talloc_array(NULL, json_t *, n_files);
  if (jcfgs==NULL) {
    tr_crit("tr_parse_config_files: cannot allocate JSON structure array");
    goto cleanup;
  }
  for (ii=0; ii<n_files; ii++) {
    jcfgs[ii]=tr_cfg_parse_one_config_file(files_with_paths[ii]);
    if (jcfgs[ii]==NULL) {
      tr_err("tr_parse_config: Error parsing JSON in %s", files_with_paths[ii]);
      tr_cfg_parse_free_jcfgs(ii, jcfgs); /* frees the JSON objects and the jcfgs array */
      jcfgs=NULL;
      goto cleanup;
    }
  }
cleanup:
  if (jcfgs)
    talloc_steal(mem_ctx, jcfgs); /* give this to the caller's context if we succeeded */
  talloc_free(tmp_ctx);
  return jcfgs;
}

/* define a type for config parse functions */
typedef TR_CFG_RC (TR_CFG_PARSE_FN)(TR_CFG *, json_t *);
/**
 * Helper function to parse a collection of JSON structures using a generic parse function.
 *
 * @param cfg Config structure to receive results
 * @param parse_fn Function to apply
 * @param n_jcfg Number of JSON structures in the array
 * @param jcfgs Pointer to an array of decoded JSON structures
 * @param key Key to extract from each jcfg before parsing, or NULL to use the object itself
 * @return TR_CFG_SUCCESS on success, _FAIL or an error code on failure
 */
static TR_CFG_RC tr_cfg_parse_helper(TR_CFG *cfg,
                                     TR_CFG_PARSE_FN parse_fn,
                                     unsigned int n_jcfg,
                                     json_t **jcfgs,
                                     const char *key)
{
  size_t ii=0;
  json_t *this_jcfg=NULL;
  TR_CFG_RC ret=TR_CFG_ERROR;

  if ((cfg==NULL) || (jcfgs==NULL) || (parse_fn==NULL))
    return TR_CFG_ERROR;

  for (ii=0; ii<n_jcfg; ii++) {
    if (key)
      this_jcfg = json_object_get(jcfgs[ii], key);
    else
      this_jcfg = jcfgs[ii];

    /* do not try to parse a missing jcfg */
    if (this_jcfg == NULL)
      continue;

    ret=parse_fn(cfg, this_jcfg);
    if (ret!=TR_CFG_SUCCESS)
      break;
  }
  return ret;
}


/**
 *  Reads configuration files in config_dir ("" or "./" will use the current directory).
 *
 * @param cfg_mgr Configuration manager
 * @param n_files Number of entries in cfg_files
 * @param files_with_paths Array of filenames with path to load
 * @return TR_CFG_SUCCESS on success, TR_CFG_ERROR or a more specific error on failure
 */
TR_CFG_RC tr_parse_config(TR_CFG_MGR *cfg_mgr, unsigned int n_files, char **files_with_paths)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  json_t **jcfgs=NULL;
  TR_CFG_RC cfg_rc=TR_CFG_ERROR;

  if ((!cfg_mgr) || (!files_with_paths)) {
    cfg_rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  /* get a fresh config to fill in, freeing old one if needed */
  if (cfg_mgr->new != NULL)
    tr_cfg_free(cfg_mgr->new);
  cfg_mgr->new=tr_cfg_new(tmp_ctx); /* belongs to the temporary context for now */
  if (cfg_mgr->new == NULL) {
    cfg_rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  /* first parse the json */
  jcfgs=tr_cfg_parse_config_files(tmp_ctx, n_files, files_with_paths);
  if (jcfgs==NULL) {
    cfg_rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  cfg_mgr->new->peers=trp_ptable_new(cfg_mgr); /* not sure why this isn't in cfg_mgr->new's context */

  /* now run through the parsers on the JSON */
  if ((TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_internal, n_files, jcfgs, "tr_internal"))) ||
      (TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_local_orgs, n_files, jcfgs, NULL))) ||
      (TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_peer_orgs, n_files, jcfgs, NULL))) ||
      (TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_default_servers, n_files, jcfgs,
                                                      NULL))) ||
      (TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_comms, n_files, jcfgs, NULL))))
    goto cleanup; /* cfg_rc was set above */

  /* make sure we got a complete, consistent configuration */
  if (TR_CFG_SUCCESS != tr_cfg_validate(cfg_mgr->new)) {
    tr_err("tr_parse_config: Error: INVALID CONFIGURATION");
    cfg_rc=TR_CFG_ERROR;
    goto cleanup;
  }

  /* success! */
  talloc_steal(cfg_mgr, cfg_mgr->new); /* hand this over to the cfg_mgr context */
  cfg_rc=TR_CFG_SUCCESS;

cleanup:
  if (jcfgs!=NULL)
    tr_cfg_parse_free_jcfgs(n_files, jcfgs);
  talloc_free(tmp_ctx);
  return cfg_rc;
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

static int is_cfg_file(const struct dirent *dent) {
  int n;

  /* Only accept filenames ending in ".cfg" and starting with a character
   * other than an ASCII '.' */

  /* filename must be at least 4 characters long to be acceptable */
  n=strlen(dent->d_name);
  if (n < 4) {
    return 0;
  }

  /* filename must not start with '.' */
  if ('.' == dent->d_name[0]) {
    return 0;
  }

  /* If the above passed and the last four characters of the filename are .cfg, accept.
   * (n.b., assumes an earlier test checked that the name is >= 4 chars long.) */
  if (0 == strcmp(&(dent->d_name[n-4]), ".cfg")) {
    return 1;
  }

  /* otherwise, return false. */
  return 0;
}

/* Find configuration files in a particular directory. Returns the
 * number of entries found, 0 if none are found, or <0 for some
 * errors. If n>=0, the cfg_files parameter will contain a newly
 * allocated array of pointers to struct dirent entries, as returned
 * by scandir(). These can be freed with tr_free_config_file_list().
 */
int tr_find_config_files(const char *config_dir, struct dirent ***cfg_files) {
  int n = 0;
  
  n = scandir(config_dir, cfg_files, is_cfg_file, alphasort);

  if (n < 0) {
    perror("scandir");
    tr_debug("tr_find_config: scandir error trying to scan %s.", config_dir);
  } 

  return n;
}

/* Free memory allocated for configuration file list returned from tr_find_config_files().
 * This can be called regardless of the return value of tr_find_config_values(). */
void tr_free_config_file_list(int n, struct dirent ***cfg_files) {
  int ii;

  /* if n < 0, then scandir did not allocate anything because it failed */
  if((n>=0) && (*cfg_files != NULL)) {
    for(ii=0; ii<n; ii++) {
      free((*cfg_files)[ii]);
    }
    free(*cfg_files); /* safe even if n==0 */
    *cfg_files=NULL; /* this will help prevent accidentally freeing twice */
  }
}
