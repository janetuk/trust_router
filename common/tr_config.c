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
#include <tr_debug.h>
#include <tr_filter.h>
#include <trust_router/tr_constraint.h>
#include <tr_idp.h>
#include <tr.h>

void tr_print_config (TR_CFG *cfg) {
  tr_notice("tr_print_config: Logging running trust router configuration.");
  tr_print_comms(cfg->comms);
}

void tr_print_comms (TR_COMM *comm_list) {
  TR_COMM *comm = NULL;

  for (comm = comm_list; NULL != comm; comm = comm->next) {
    tr_notice("tr_print_config: Community %s:", comm->id->buf);

    tr_notice("tr_print_config:  - Member IdPs:");
    tr_print_comm_idps(comm->idp_realms);

    tr_notice("tr_print_config:  - Member RPs:");
    tr_print_comm_rps(comm->rp_realms);
  }
}

void tr_print_comm_idps (TR_IDP_REALM *idp_list) {
  TR_IDP_REALM *idp = NULL;

  for (idp = idp_list; NULL != idp; idp = idp->comm_next) {
    tr_notice("tr_print_config:    - @%s", idp->realm_id->buf);
  }
}

void tr_print_comm_rps(TR_RP_REALM *rp_list) {
  TR_RP_REALM *rp = NULL;

  for (rp = rp_list; NULL != rp; rp = rp->next) {
    tr_notice("tr_print_config:    - %s", rp->realm_name->buf);
  }
}

TR_CFG *tr_cfg_new(TALLOC_CTX *mem_ctx)
{
  return talloc_zero(mem_ctx, TR_CFG);
}

void tr_cfg_free (TR_CFG *cfg) {
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

static TR_CFG_RC tr_cfg_parse_internal(TR_CFG *trc, json_t *jcfg)
{
  json_t *jint = NULL;
  json_t *jmtd = NULL;
  json_t *jtidsp = NULL;
  json_t *jtrpsp = NULL;
  json_t *jhname = NULL;
  json_t *jlog = NULL;
  json_t *jconthres = NULL;
  json_t *jlogthres = NULL;
  json_t *jcfgpoll = NULL;
  json_t *jcfgsettle = NULL;
  json_t *jroutesweep = NULL;
  json_t *jrouteupdate = NULL;
  json_t *jrouteconnect = NULL;

  if ((!trc) || (!jcfg))
    return TR_CFG_BAD_PARAMS;

  if (NULL == trc->internal) {
    if (NULL == (trc->internal = talloc_zero(trc, TR_CFG_INTERNAL)))
      return TR_CFG_NOMEM;
  }

  if (NULL != (jint = json_object_get(jcfg, "tr_internal"))) {
    if (NULL != (jmtd = json_object_get(jint, "max_tree_depth"))) {
      if (json_is_number(jmtd)) {
        trc->internal->max_tree_depth = json_integer_value(jmtd);
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, max_tree_depth is not a number.");
        return TR_CFG_NOPARSE;
      }
    } else {
      /* If not configured, use the default */
      trc->internal->max_tree_depth = TR_DEFAULT_MAX_TREE_DEPTH;
    }
    if (NULL != (jtidsp = json_object_get(jint, "tids_port"))) {
      if (json_is_number(jtidsp)) {
        trc->internal->tids_port = json_integer_value(jtidsp);
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, tids_port is not a number.");
        return TR_CFG_NOPARSE;
      }
    } else {
      /* If not configured, use the default */
      trc->internal->tids_port = TR_DEFAULT_TIDS_PORT;
    }
    if (NULL != (jtrpsp = json_object_get(jint, "trps_port"))) {
      if (json_is_number(jtrpsp)) {
        trc->internal->trps_port = json_integer_value(jtrpsp);
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, trps_port is not a number.");
        return TR_CFG_NOPARSE;
      }
    } else {
      /* If not configured, use the default */
      trc->internal->trps_port = TR_DEFAULT_TRPS_PORT;
    }
    if (NULL != (jhname = json_object_get(jint, "hostname"))) {
      if (json_is_string(jhname)) {
        trc->internal->hostname = json_string_value(jhname);
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, hostname is not a string.");
        return TR_CFG_NOPARSE;
      }
    }
    if (NULL != (jcfgpoll = json_object_get(jint, "cfg_poll_interval"))) {
      if (json_is_number(jcfgpoll)) {
        trc->internal->cfg_poll_interval = json_integer_value(jcfgpoll);
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, cfg_poll_interval is not a number.");
        return TR_CFG_NOPARSE;
      }
    } else {
      trc->internal->cfg_poll_interval = TR_CFGWATCH_DEFAULT_POLL;
    }

    if (NULL != (jcfgsettle = json_object_get(jint, "cfg_settling_time"))) {
      if (json_is_number(jcfgsettle)) {
        trc->internal->cfg_settling_time = json_integer_value(jcfgsettle);
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, cfg_settling_time is not a number.");
        return TR_CFG_NOPARSE;
      }
    } else {
      trc->internal->cfg_settling_time = TR_CFGWATCH_DEFAULT_SETTLE;
    }

    if (NULL != (jrouteconnect = json_object_get(jint, "trp_connect_interval"))) {
      if (json_is_number(jrouteconnect)) {
        trc->internal->trp_connect_interval = json_integer_value(jrouteconnect);
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, trp_connect_interval is not a number.");
        return TR_CFG_NOPARSE;
      }
    } else {
      /* if not configured, use the default */
      trc->internal->trp_connect_interval=TR_DEFAULT_TRP_CONNECT_INTERVAL;
    }

    if (NULL != (jroutesweep = json_object_get(jint, "trp_sweep_interval"))) {
      if (json_is_number(jroutesweep)) {
        trc->internal->trp_sweep_interval = json_integer_value(jroutesweep);
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, trp_sweep_interval is not a number.");
        return TR_CFG_NOPARSE;
      }
    } else {
      /* if not configured, use the default */
      trc->internal->trp_sweep_interval=TR_DEFAULT_TRP_SWEEP_INTERVAL;
    }

    if (NULL != (jrouteupdate = json_object_get(jint, "trp_update_interval"))) {
      if (json_is_number(jrouteupdate)) {
        trc->internal->trp_update_interval = json_integer_value(jrouteupdate);
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, trp_update_interval is not a number.");
        return TR_CFG_NOPARSE;
      }
    } else {
      /* if not configured, use the default */
      trc->internal->trp_update_interval=TR_DEFAULT_TRP_UPDATE_INTERVAL;
    }

    if (NULL != (jlog = json_object_get(jint, "logging"))) {
      if (NULL != (jlogthres = json_object_get(jlog, "log_threshold"))) {
        if (json_is_string(jlogthres)) {
          trc->internal->log_threshold = str2sev(json_string_value(jlogthres));
        } else {
          tr_debug("tr_cfg_parse_internal: Parsing error, log_threshold is not a string.");
          return TR_CFG_NOPARSE;
        }
      } else {
        /* If not configured, use the default */
        trc->internal->log_threshold = TR_DEFAULT_LOG_THRESHOLD;
      }

      if (NULL != (jconthres = json_object_get(jlog, "console_threshold"))) {
        if (json_is_string(jconthres)) {
            trc->internal->console_threshold = str2sev(json_string_value(jconthres));
        } else {
          tr_debug("tr_cfg_parse_internal: Parsing error, console_threshold is not a string.");
          return TR_CFG_NOPARSE;
        }
      } else {
        /* If not configured, use the default */
        trc->internal->console_threshold = TR_DEFAULT_CONSOLE_THRESHOLD;
      }
    } else {
        /* If not configured, use the default */
        trc->internal->console_threshold = TR_DEFAULT_CONSOLE_THRESHOLD;
        trc->internal->log_threshold = TR_DEFAULT_LOG_THRESHOLD;
    }

    tr_debug("tr_cfg_parse_internal: Internal config parsed.");
    return TR_CFG_SUCCESS;
  }
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
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_FILTER *filt=NULL;
  json_t *jfaction=NULL;
  json_t *jfspecs=NULL;
  json_t *jffield=NULL;
  json_t *jfmatch=NULL;
  json_t *jrc=NULL;
  json_t *jdc=NULL;
  int i=0, j=0;

  *rc=TR_CFG_ERROR;

  if ((jfilt==NULL) || (rc==NULL)) {
    tr_err("tr_cfg_parse_one_filter: null argument");
    *rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }
    
  if (NULL==(filt=tr_filter_new(tmp_ctx))) {
    tr_err("tr_cfg_parse_one_filter: Out of memory.");
    *rc=TR_CFG_NOMEM;
    goto cleanup;
  }
  tr_filter_set_type(filt, ftype);

  /* make sure we have space to represent the filter */
  if (json_array_size(jfilt) > TR_MAX_FILTER_LINES) {
    tr_err("tr_cfg_parse_one_filter: Filter has too many lines, maximum of %d.", TR_MAX_FILTER_LINES);
    *rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  /* For each entry in the filter... */
  for (i=0; i < json_array_size(jfilt); i++) {
    if ((NULL==(jfaction=json_object_get(json_array_get(jfilt, i), "action"))) ||
        (!json_is_string(jfaction))) {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter action.");
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    }
 
    if ((NULL==(jfspecs=json_object_get(json_array_get(jfilt, i), "filter_specs"))) ||
        (!json_is_array(jfspecs)) ||
        (0==json_array_size(jfspecs))) {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter specs.");
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    }
  
    if (TR_MAX_FILTER_SPECS < json_array_size(jfspecs)) {
      tr_debug("tr_cfg_parse_one_filter: Filter has too many filter_specs, maximimum of %d.", TR_MAX_FILTER_SPECS);
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    }

    if (NULL==(filt->lines[i]=tr_fline_new(filt))) {
      tr_debug("tr_cfg_parse_one_filter: Out of memory allocating filter line %d.", i+1);
      *rc=TR_CFG_NOMEM;
      goto cleanup;
    }

    if (!strcmp(json_string_value(jfaction), "accept")) {
      filt->lines[i]->action=TR_FILTER_ACTION_ACCEPT;
    }
    else if (!strcmp(json_string_value(jfaction), "reject")) {
      filt->lines[i]->action=TR_FILTER_ACTION_REJECT;
    }
    else {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter action, unknown action' %s'.", json_string_value(jfaction));
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    }

    if (NULL!=(jrc=json_object_get(json_array_get(jfilt, i), "realm_constraints"))) {
      if (!json_is_array(jrc)) {
        tr_err("tr_cfg_parse_one_filter: cannot parse realm_constraints, not an array.");
        *rc=TR_CFG_NOPARSE;
        goto cleanup;
      } else if (json_array_size(jrc)>TR_MAX_CONST_MATCHES) {
        tr_err("tr_cfg_parse_one_filter: realm_constraints has too many entries, maximum of %d.",
               TR_MAX_CONST_MATCHES);
        *rc=TR_CFG_NOPARSE;
        goto cleanup;
      } else if (json_array_size(jrc)>0) {
        /* ok we actually have entries to process */
        if (NULL==(filt->lines[i]->realm_cons=tr_cfg_parse_one_constraint(filt->lines[i], "realm", jrc, rc))) {
          tr_debug("tr_cfg_parse_one_filter: Error parsing realm constraint");
          *rc=TR_CFG_NOPARSE;
          goto cleanup;
        }
      }
    }
  }

  if (NULL!=(jdc=json_object_get(json_array_get(jfilt, i), "domain_constraints"))) {
    if (!json_is_array(jdc)) {
      tr_err("tr_cfg_parse_one_filter: cannot parse domain_constraints, not an array.");
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    } else if (json_array_size(jdc)>TR_MAX_CONST_MATCHES) {
      tr_err("tr_cfg_parse_one_filter: domain_constraints has too many entries, maximum of %d.",
             TR_MAX_CONST_MATCHES);
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    } else if (json_array_size(jdc)>0) {
      if (NULL==(filt->lines[i]->domain_cons=tr_cfg_parse_one_constraint(filt->lines[i], "domain", jdc, rc))) {
        tr_debug("tr_cfg_parse_one_filter: Error parsing domain constraint");
        *rc=TR_CFG_NOPARSE;
        goto cleanup;
      }
    }
  }

  /*For each filter spec within the filter line... */
  for (j=0; j <json_array_size(jfspecs); j++) {
    if ((NULL==(jffield=json_object_get(json_array_get(jfspecs, j), "field"))) ||
        (!json_is_string(jffield)) ||
        (NULL==(jfmatch=json_object_get(json_array_get(jfspecs, j), "match"))) ||
        (!json_is_string(jfmatch))) {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter field and match for filter spec %d, filter line %d.", i, j);
      *rc=TR_CFG_NOPARSE;
      goto cleanup;
    }

    if (NULL==(filt->lines[i]->specs[j]=tr_fspec_new(filt->lines[i]))) {
      tr_debug("tr_cfg_parse_one_filter: Out of memory.");
      *rc=TR_CFG_NOMEM;
      goto cleanup;
    }

    if ((NULL==(filt->lines[i]->specs[j]->field=tr_new_name(json_string_value(jffield)))) ||
          (NULL==(filt->lines[i]->specs[j]->match=tr_new_name(json_string_value(jfmatch))))) {
      tr_debug("tr_cfg_parse_one_filter: Out of memory.");
      *rc=TR_CFG_NOMEM;
      goto cleanup;
    }
  }
  
  *rc=TR_CFG_SUCCESS;
  talloc_steal(mem_ctx, filt);
  
 cleanup:
  talloc_free(tmp_ctx);
  return filt;
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

static TR_APC *tr_cfg_parse_apc(TALLOC_CTX *mem_ctx, json_t *japc, TR_CFG_RC *rc)
{
  TR_APC *apc=NULL;
  TR_NAME *name=NULL;
  
  *rc = TR_CFG_SUCCESS;         /* presume success */

  if ((!japc) || (!rc) || (!json_is_string(japc))) {
    tr_debug("tr_cfg_parse_apc: Bad parameters.");
    if (rc) 
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  apc=tr_apc_new(mem_ctx);
  if (apc==NULL) {
    tr_debug("tr_cfg_parse_apc: Out of memory.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  name=tr_new_name(json_string_value(japc));
  if (name==NULL) {
    tr_debug("tr_cfg_parse_apc: No memory for APC name.");
    tr_apc_free(apc);
    *rc = TR_CFG_NOMEM;
    return NULL;
  }
  tr_apc_set_id(apc, name); /* apc is now responsible for freeing the name */

  return apc;
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

/* Parse the identity provider object from a realm and fill in the given TR_IDP_REALM. */
static TR_CFG_RC tr_cfg_parse_idp(TR_IDP_REALM *idp, json_t *jidp)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_APC *apcs=NULL;
  TR_AAA_SERVER *aaa=NULL;
  TR_CFG_RC rc=TR_CFG_ERROR;

  if (jidp==NULL)
    goto cleanup;

  idp->origin=TR_REALM_LOCAL; /* if we're parsing it from a config file, it's local */
  idp->shared_config=tr_cfg_parse_shared_config(json_object_get(jidp, "shared_config"), &rc);
  if (rc!=TR_CFG_SUCCESS) {
    tr_err("tr_cfg_parse_idp: missing or malformed shared_config specification");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  apcs=tr_cfg_parse_apc(tmp_ctx, json_object_get(jidp, "apc"), &rc);
  if ((rc!=TR_CFG_SUCCESS) || (apcs==NULL)) {
    tr_err("tr_cfg_parse_idp: unable to parse APC");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }
  tr_debug("tr_cfg_parse_idp: APC=\"%.*s\"",
           apcs->id->len,
           apcs->id->buf);

  aaa=tr_cfg_parse_aaa_servers(idp, json_object_get(jidp, "aaa_servers"), &rc);
  if ((rc!=TR_CFG_SUCCESS) || (aaa==NULL)) {
    tr_err("tr_cfg_parse_idp: unable to parse AAA servers");
    rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

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
  json_t *jremote=NULL;
  json_t *jscfg=NULL;
  json_t *jsrvrs=NULL;
  json_t *japcs=NULL;
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
      realms=tr_idp_realm_add(realms, new_realm);
    }
  }
  
  *rc=TR_CFG_SUCCESS;
  talloc_steal(mem_ctx, realms);

cleanup:
  talloc_free(tmp_ctx);
  return realms;
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

/* Update the community information with data from a new batch of IDP realms.
 * May partially add realms if there is a failure, no guarantees.
 * Call like comms=tr_comm_idp_update(comms, new_realms, &rc) */
static TR_COMM *tr_cfg_comm_idp_update(TALLOC_CTX *mem_ctx, TR_COMM *comms, TR_IDP_REALM *new_realms, TR_CFG_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM *comm=NULL; /* community looked up in comms table */
  TR_COMM *new_comms=NULL; /* new communities as we create them */
  TR_IDP_REALM *realm=NULL;
  TR_APC *apc=NULL; /* apc of one realm */

  if (rc==NULL) {
    *rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  /* start with an empty list communities, then fill that in */
  for (realm=new_realms; realm!=NULL; realm=realm->next) {
    for (apc=realm->apcs; apc!=NULL; apc=apc->next) {
      comm=tr_comm_lookup(comms, apc->id);
      if (comm==NULL) {
        comm=tr_comm_new(tmp_ctx);
        if (comm==NULL) {
          tr_debug("tr_cfg_comm_idp_update: unable to allocate new community.");
          *rc=TR_CFG_NOMEM;
          goto cleanup;
        }
        /* fill in the community with info */
        comm->type=TR_COMM_APC; /* realms added this way are in APCs */
        comm->expiration_interval=TR_DEFAULT_APC_EXPIRATION_INTERVAL;
        comm->id=tr_dup_name(apc->id);
        tr_comm_add_idp_realm(comm, realm);
        new_comms=tr_comm_add(new_comms, comm);
      } else {
        /* add this realm to the comm */
        tr_comm_add_idp_realm(comm, realm);
      }
    }
  }

  /* we successfully built a list, add it to the other list */
  comms=tr_comm_add(comms, new_comms);
  talloc_steal(mem_ctx, comms);
 cleanup:
  talloc_free(tmp_ctx);
  return comms;
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
  TR_RP_REALM *new_rp_realms=NULL;

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

#if 0
    new_rp_realms=tr_cfg_parse_rp_realms(tmp_ctx, j_realms, &rc);
    if (rc!=TR_CFG_SUCCESS)
      goto cleanup;
#endif
  }
  retval=TR_CFG_SUCCESS;
  
cleanup:
  /* if we succeeded, link things to the configuration and move out of tmp context */
  if (retval==TR_CFG_SUCCESS) {
    if (new_idp_realms!=NULL) {
      trc->idp_realms=tr_idp_realm_add(trc->idp_realms, new_idp_realms); /* fixes talloc contexts except for head*/
      talloc_steal(trc, trc->idp_realms); /* make sure the head is in the right context */
      trc->comms=tr_cfg_comm_idp_update(trc, trc->comms, new_idp_realms, &rc); /* put realm info in community table */
    }
#if 0
    if (new_rp_realms!=NULL)
      trc->rp_realms=tr_rp_realm_add(trc->rp_realms, new_rp_realms); /* fixes talloc contexts */
#endif
  }

  talloc_free(tmp_ctx);
  return rc;
}

/* Parse local organizations if present. Returns success if there are none. On failure, the configuration is unreliable. */
static TR_CFG_RC tr_cfg_parse_local_orgs(TR_CFG *trc, json_t *jcfg)
{
  json_t *jlocorgs=NULL;
  int ii=0;

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

  if (NULL == trc->comms) {
    tr_debug("tr_cfg_validate: Error: No Communities configured");
    rc = TR_CFG_ERROR;
  }

  if ((NULL == trc->default_servers) && (NULL == trc->idp_realms)) {
    tr_debug("tr_cfg_validate: Error: No default servers or IDPs configured.");
    rc = TR_CFG_ERROR;
  }
  
  return rc;
}

/* Join two paths and return a pointer to the result. This should be freed
 * via talloc_free. Returns NULL on failure. */
static char *join_paths(TALLOC_CTX *mem_ctx, const char *p1, const char *p2)
{
  return talloc_asprintf(mem_ctx, "%s/%s", p1, p2); /* returns NULL on a failure */
}

TR_CFG_RC tr_cfg_parse_one_config_file(TR_CFG *cfg, const char *file_with_path)
{
  json_t *jcfg=NULL;
  json_t *jser=NULL;
  json_error_t rc;

  if (NULL==(jcfg=json_load_file(file_with_path, 
                                 JSON_DISABLE_EOF_CHECK, &rc))) {
    tr_debug("tr_parse_config: Error parsing config file %s.", 
             file_with_path);
    return TR_CFG_NOPARSE;
  }

  // Look for serial number and log it if it exists
  if (NULL!=(jser=json_object_get(jcfg, "serial_number"))) {
    if (json_is_number(jser)) {
      tr_notice("tr_read_config: Attempting to load revision %" JSON_INTEGER_FORMAT " of '%s'.",
                json_integer_value(jser),
                file_with_path);
    }
  }

  /* TODO: parse using the new functions */
#if 0
  if ((TR_CFG_SUCCESS != tr_cfg_parse_internal(cfg, jcfg)) ||
      (TR_CFG_SUCCESS != tr_cfg_parse_rp_clients(cfg, jcfg)) ||
      (TR_CFG_SUCCESS != tr_cfg_parse_idp_realms(cfg, jcfg)) ||
      (TR_CFG_SUCCESS != tr_cfg_parse_default_servers(cfg, jcfg)) ||
      (TR_CFG_SUCCESS != tr_cfg_parse_comms(cfg, jcfg))) {

  }
#endif
  if (TR_CFG_SUCCESS != tr_cfg_parse_local_orgs(cfg, jcfg))
    return TR_CFG_ERROR;

  return TR_CFG_SUCCESS;
}

/* Reads configuration files in config_dir ("" or "./" will use the current directory). */
TR_CFG_RC tr_parse_config(TR_CFG_MGR *cfg_mgr, const char *config_dir, int n, struct dirent **cfg_files)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  json_t *jcfg;
  json_t *jser;
  json_error_t rc;
  char *file_with_path;
  int ii;
  TR_CFG_RC cfg_rc=TR_CFG_ERROR;

  if ((!cfg_mgr) || (!cfg_files) || (n<=0)) {
    cfg_rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  if (cfg_mgr->new != NULL)
    tr_cfg_free(cfg_mgr->new);
  cfg_mgr->new=tr_cfg_new(tmp_ctx); /* belongs to the temporary context for now */
  if (cfg_mgr->new == NULL) {
    cfg_rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  /* Parse configuration information from each config file */
  for (ii=0; ii<n; ii++) {
    file_with_path=join_paths(tmp_ctx, config_dir, cfg_files[ii]->d_name); /* must free result with talloc_free */
    if(file_with_path == NULL) {
      tr_crit("tr_parse_config: error joining path.");
      cfg_rc=TR_CFG_NOMEM;
      goto cleanup;
    }
    tr_debug("tr_parse_config: Parsing %s.", cfg_files[ii]->d_name); /* print the filename without the path */
    cfg_rc=tr_cfg_parse_one_config_file(cfg_mgr->new, file_with_path);
    if (cfg_rc!=TR_CFG_SUCCESS) {
      tr_crit("tr_parse_config: error parsing %s", file_with_path);
      goto cleanup;
    }
    talloc_free(file_with_path); /* done with filename */
  }

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

  for (cfg_idp = tr_cfg->idp_realms; NULL != cfg_idp; cfg_idp = cfg_idp->next) {
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
  int i;

  if ((!tr_cfg) || (!rp_gss)) {
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  for (cfg_rp = tr_cfg->rp_clients; NULL != cfg_rp; cfg_rp = cfg_rp->next) {
    for (i = 0; i < TR_MAX_GSS_NAMES; i++) {
      if (!tr_name_cmp (rp_gss, cfg_rp->gss_names[i])) {
        tr_debug("tr_cfg_find_rp: Found %s.", rp_gss->buf);
        return cfg_rp;
      }
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
int tr_find_config_files (const char *config_dir, struct dirent ***cfg_files) {
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
