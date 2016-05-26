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

#include <tr_config.h>
#include <tr_debug.h>
#include <tr.h>
#include <tr_filter.h>
#include <trust_router/tr_constraint.h>

void tr_print_config (FILE *stream, TR_CFG *cfg) {
  fprintf(stream, "tr_print_config: Not yet implemented.");
  return;
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

static TR_CFG_RC tr_cfg_parse_internal (TR_CFG *trc, json_t *jcfg) {
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
    }
    if (NULL != (jcfgsettle = json_object_get(jint, "cfg_settle_count"))) {
      if (json_is_number(jcfgsettle)) {
	trc->internal->cfg_settle_count = json_integer_value(jcfgsettle);
      } else {
	tr_debug("tr_cfg_parse_internal: Parsing error, cfg_settle_count is not a number.");
	return TR_CFG_NOPARSE;
      }
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

static TR_CONSTRAINT *tr_cfg_parse_one_constraint (TR_CFG *trc, char *ctype, json_t *jc, TR_CFG_RC *rc)
{
  TR_CONSTRAINT *cons;
  int i;

  if ((!trc) || (!ctype) || (!jc) || (!rc) ||
      (!json_is_array(jc)) ||
      (0 >= json_array_size(jc)) ||
      (TR_MAX_CONST_MATCHES < json_array_size(jc)) ||
      (!json_is_string(json_array_get(jc, 0)))) {
    tr_debug("tr_cfg_parse_one_constraint: config error.");
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  if (NULL == (cons = talloc_zero(trc, TR_CONSTRAINT))) {
    tr_debug("tr_cfg_parse_one_constraint: Out of memory (cons).");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  if (NULL == (cons->type = tr_new_name(ctype))) {
    tr_debug("tr_cfg_parse_one_constraint: Out of memory (type).");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  for (i = 0; i < json_array_size(jc); i++) {
    cons->matches[i] = tr_new_name((char *)(json_string_value(json_array_get(jc, i))));
  }

  return cons;
}

static TR_FILTER *tr_cfg_parse_one_filter (TR_CFG *trc, json_t *jfilt, TR_CFG_RC *rc)
{
  TR_FILTER *filt = NULL;
  json_t *jftype = NULL;
  json_t *jfls = NULL;
  json_t *jfaction = NULL;
  json_t *jfspecs = NULL;
  json_t *jffield = NULL;
  json_t *jfmatch = NULL;
  json_t *jrc = NULL;
  json_t *jdc = NULL;
  int i = 0, j = 0;

  if ((NULL == (jftype = json_object_get(jfilt, "type"))) ||
      (!json_is_string(jftype))) {
    tr_debug("tr_cfg_parse_one_filter: Error parsing filter type.");
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  if ((NULL == (jfls = json_object_get(jfilt, "filter_lines"))) ||
      (!json_is_array(jfls))) {
    tr_debug("tr_cfg_parse_one_filter: Error parsing filter type.");
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  if (TR_MAX_FILTER_LINES < json_array_size(jfls)) {
    tr_debug("tr_cfg_parse_one_filter: Filter has too many filter_lines, maximimum of %d.", TR_MAX_FILTER_LINES);
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  if (NULL == (filt = talloc_zero(trc, TR_FILTER))) {
    tr_debug("tr_cfg_parse_one_filter: Out of memory.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  if (!strcmp(json_string_value(jftype), "rp_permitted")) {
    filt->type = TR_FILTER_TYPE_RP_PERMITTED;
  }
  else {
    tr_debug("tr_cfg_parse_one_filter: Error parsing filter type, unknown type '%s'.", json_string_value(jftype));
    *rc = TR_CFG_NOPARSE;
    tr_filter_free(filt);
    return NULL;
  }

  /* For each filter line... */
  for (i = 0; i < json_array_size(jfls); i++) {

    if ((NULL == (jfaction = json_object_get(json_array_get(jfls, i), "action"))) ||
	(!json_is_string(jfaction))) {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter action.");
      *rc = TR_CFG_NOPARSE;
      tr_filter_free(filt);
      return NULL;
    }
 
    if ((NULL == (jfspecs = json_object_get(json_array_get(jfls, i), "filter_specs"))) ||
	(!json_is_array(jfspecs)) ||
	(0 == json_array_size(jfspecs))) {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter specs.");
      *rc = TR_CFG_NOPARSE;
      tr_filter_free(filt);
      return NULL;
    }
  
    if (TR_MAX_FILTER_SPECS < json_array_size(jfspecs)) {
      tr_debug("tr_cfg_parse_one_filter: Filter has too many filter_specs, maximimum of %d.", TR_MAX_FILTER_SPECS);
      *rc = TR_CFG_NOPARSE;
      tr_filter_free(filt);
      return NULL;
    }

    if (NULL == (filt->lines[i] = talloc_zero(trc, TR_FLINE))) {
      tr_debug("tr_cfg_parse_one_filter: Out of memory (fline).");
      *rc = TR_CFG_NOMEM;
      tr_filter_free(filt);
      return NULL;
    }

    if (!strcmp(json_string_value(jfaction), "accept")) {
	filt->lines[i]->action = TR_FILTER_ACTION_ACCEPT;
    }
    else if (!strcmp(json_string_value(jfaction), "reject")) {
      filt->lines[i]->action = TR_FILTER_ACTION_REJECT;
    }
    else {
      tr_debug("tr_cfg_parse_one_filter: Error parsing filter action, unknown action' %s'.", json_string_value(jfaction));
      *rc = TR_CFG_NOPARSE;
      tr_filter_free(filt);
      return NULL;
    }

    if ((NULL != (jrc = json_object_get(json_array_get(jfls, i), "realm_constraints"))) &&
	(json_is_array(jrc)) &&
	(0 != json_array_size(jrc)) &&
	(TR_MAX_CONST_MATCHES >= json_array_size(jrc))) {

      if (NULL == (filt->lines[i]->realm_cons = tr_cfg_parse_one_constraint(trc, "realm", jrc, rc))) {
	tr_debug("tr_cfg_parse_one_filter: Error parsing realm constraint");
      tr_filter_free(filt);
      return NULL;
      }
    }

    if ((NULL != (jdc = json_object_get(json_array_get(jfls, i), "domain_constraints"))) &&
	(json_is_array(jdc)) &&
	(0 != json_array_size(jdc)) &&
	(TR_MAX_CONST_MATCHES >= json_array_size(jdc))) {

      if (NULL == (filt->lines[i]->domain_cons = tr_cfg_parse_one_constraint(trc, "domain", jdc, rc))) {
	tr_debug("tr_cfg_parse_one_filter: Error parsing domain constraint");
      tr_filter_free(filt);
      return NULL;
      }
    }

    /*For each filter spec within the filter line... */
    for (j = 0; j <json_array_size(jfspecs); j++) {
      
      if ((NULL == (jffield = json_object_get(json_array_get(jfspecs, j), "field"))) ||
	  (!json_is_string(jffield)) ||
	  (NULL == (jfmatch = json_object_get(json_array_get(jfspecs, j), "match"))) ||
	  (!json_is_string(jfmatch))) {
	tr_debug("tr_cfg_parse_one_filter: Error parsing filter field and match for filter spec %d, filter line %d.", i, j);
	*rc = TR_CFG_NOPARSE;
	tr_filter_free(filt);
	return NULL;
      }

      if (NULL == (filt->lines[i]->specs[j] = talloc_zero(trc, TR_FSPEC))) {
	tr_debug("tr_cfg_parse_one_filter: Out of memory.");
	*rc = TR_CFG_NOMEM;
	tr_filter_free(filt);
	return NULL;
      }

      if ((NULL == (filt->lines[i]->specs[j]->field = tr_new_name((char *)json_string_value(jffield)))) ||
	  (NULL == (filt->lines[i]->specs[j]->match = tr_new_name((char *)json_string_value(jfmatch))))) {
	tr_debug("tr_cfg_parse_one_filter: Out of memory.");
	*rc = TR_CFG_NOMEM;
	tr_filter_free(filt);
	return NULL;
      }
    }
  }

  return filt;
}

static TR_RP_CLIENT *tr_cfg_parse_one_rp_client (TR_CFG *trc, json_t *jrp, TR_CFG_RC *rc)
{
  TR_RP_CLIENT *rp = NULL;
  json_t *jgns = NULL;
  json_t *jfilt = NULL;
  json_t *jftype = NULL;
  int i = 0;

  if ((!trc) || (!jrp) || (!rc)) {
    tr_debug("tr_cfg_parse_one_rp_realm: Bad parameters.");
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  if ((NULL == (jgns = json_object_get(jrp, "gss_names"))) ||
      (!json_is_array(jgns))) {
    tr_debug("tr_cfg_parse_one_rp_client: Error parsing RP client configuration, no GSS names.");
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  /* TBD -- Support more than one filter per RP client? */
  if (NULL == (jfilt = json_object_get(jrp, "filter"))) {
    tr_debug("tr_cfg_parse_one_rp_client: Error parsing RP client configuration, no filter.");
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  /* We only support rp_permitted filters for RP clients */
  if ((NULL == (jftype = json_object_get(jfilt, "type"))) ||
      (!json_is_string(jftype)) ||
      (strcmp(json_string_value(jftype), "rp_permitted"))) {
    tr_debug("tr_cfg_parse_one_rp_client: Error parsing RP client filter type.");
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  if (TR_MAX_GSS_NAMES < json_array_size(jgns)) {
    tr_debug("tr_cfg_parse_one_rp_client: RP Client has too many GSS Names.");
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  if (NULL == (rp = talloc_zero(trc, TR_RP_CLIENT))) {
    tr_debug("tr_cfg_parse_one_rp_realm: Out of memory.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  /* TBD -- support more than one filter entry per RP Client? */
  if (NULL == (rp->filter = tr_cfg_parse_one_filter(trc, jfilt, rc))) {
    tr_debug("tr_cfg_parse_one_rp_client: Error parsing filter.");
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }
    
  for (i = 0; i < json_array_size(jgns); i++) {
    if (NULL == (rp->gss_names[i] = tr_new_name ((char *)json_string_value(json_array_get(jgns, i))))) {
      tr_debug("tr_cfg_parse_one_rp_client: No memory for GSS Name.");
      *rc = TR_CFG_NOMEM;
      return NULL;
    }
  }
  
  return rp;
}

static TR_CFG_RC tr_cfg_parse_rp_clients (TR_CFG *trc, json_t *jcfg) {
  json_t *jrps = NULL;
  TR_RP_CLIENT *rp = NULL;
  TR_CFG_RC rc = TR_CFG_SUCCESS;
  int i = 0;

  if ((!trc) || (!jcfg))
    return TR_CFG_BAD_PARAMS;

  if (NULL != (jrps = json_object_get(jcfg, "rp_clients"))) {

    if (!json_is_array(jrps)) {
      return TR_CFG_NOPARSE;
    }

    for (i = 0; i < json_array_size(jrps); i++) {
      if (NULL == (rp = tr_cfg_parse_one_rp_client(trc, 
						   json_array_get(jrps, i), 
						   &rc))) {
	return rc;
      }
      tr_debug("tr_cfg_parse_rp_clients: RP client configured -- first gss: %s", rp->gss_names[0]->buf);
      rp->next = trc->rp_clients;
      trc->rp_clients = rp;
    }
  }
  tr_debug("tr_cfg_parse_rp_clients: Finished (rc=%d)", rc);
  return rc;
}

static TR_AAA_SERVER *tr_cfg_parse_one_aaa_server (TR_CFG *trc, json_t *jaddr, TR_CFG_RC *rc) {
  TR_AAA_SERVER *aaa = NULL;

  if ((!trc) || (!jaddr) || (!json_is_string(jaddr))) {
    tr_debug("tr_cfg_parse_one_aaa_server: Bad parameters.");
    *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  if (NULL == (aaa = talloc_zero(trc, TR_AAA_SERVER))) {
    tr_debug("tr_cfg_parse_one_aaa_server: Out of memory.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  aaa->hostname = tr_new_name((char *)(json_string_value(jaddr)));

  return aaa;
}

static TR_AAA_SERVER *tr_cfg_parse_aaa_servers (TR_CFG *trc, json_t *jaaas, TR_CFG_RC *rc) 
{
  TR_AAA_SERVER *aaa = NULL;
  TR_AAA_SERVER *temp_aaa = NULL;
  int i = 0;

  for (i = 0; i < json_array_size(jaaas); i++) {
    if (NULL == (temp_aaa = tr_cfg_parse_one_aaa_server(trc, json_array_get(jaaas, i), rc))) {
      return NULL;
    }
    /* TBD -- IPv6 addresses */
    //    tr_debug("tr_cfg_parse_aaa_servers: Configuring AAA Server: ip_addr = %s.", inet_ntoa(temp_aaa->aaa_server_addr));
    temp_aaa->next = aaa;
    aaa = temp_aaa;
  }
  tr_debug("tr_cfg_parse_aaa_servers: Finished (rc=%d)", *rc);
  return aaa;
}

static TR_APC *tr_cfg_parse_apcs (TR_CFG *trc, json_t *japcs, TR_CFG_RC *rc)
{
  TR_APC *apc;

  *rc = TR_CFG_SUCCESS;		/* presume success */

  if ((!trc) || (!japcs) || (!rc)) {
    tr_debug("tr_cfg_parse_apcs: Bad parameters.");
    if (rc) 
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  if (NULL == (apc = talloc_zero(trc, TR_APC))) {
    tr_debug("tr_cfg_parse_apcs: Out of memory.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  /* TBD, deal with more than one APC.  In the meantime, though...                */
  /* Only parse the first APC, because we only know how to deal with one, anyway. */
  if (0 == json_array_size(japcs))
    return NULL;

  if (NULL == (apc->id = tr_new_name((char *)json_string_value(json_array_get(japcs, 0))))) {
    tr_debug("tr_cfg_parse_apcs: No memory for APC name.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  tr_debug("tr_cfg_parse_apcs: Finished (rc=%d)", *rc);
  return apc;
}

static TR_IDP_REALM *tr_cfg_parse_one_idp_realm (TR_CFG *trc, json_t *jidp, TR_CFG_RC *rc) {
  TR_IDP_REALM *idp = NULL;
  json_t *jrid = NULL;
  json_t *jscfg = NULL;
  json_t *jsrvrs = NULL;
  json_t *japcs = NULL;

  if ((!trc) || (!jidp) || (!rc)) {
    tr_debug("tr_cfg_parse_one_idp_realm: Bad parameters.");
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  if (NULL == (idp = talloc_zero(trc, TR_IDP_REALM))) {
    tr_debug("tr_cfg_parse_one_idp_realm: Out of memory.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  if ((NULL == (jrid = json_object_get(jidp, "realm_id"))) ||
      (!json_is_string(jrid)) ||
      (NULL == (jscfg = json_object_get(jidp, "shared_config"))) ||
      (!json_is_string(jscfg)) ||
      (NULL == (jsrvrs = json_object_get(jidp, "aaa_servers"))) ||
      (!json_is_array(jsrvrs))) {
    tr_debug("tr_cfg_parse_one_idp_realm: Error parsing IDP realm configuration.");
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  if (0 == strcmp(json_string_value(jscfg), "no")) {
    idp->shared_config = 0;
  } else {
    idp->shared_config = 1;
  }

  if (NULL == (idp->realm_id = tr_new_name((char *)json_string_value(jrid)))) {
    tr_debug("tr_cfg_parse_one_idp_realm: No memory for realm id.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  if (NULL == (idp->aaa_servers = tr_cfg_parse_aaa_servers(trc, jsrvrs, rc))) {
    tr_debug("tr_cfg_parse_one_idp_realm: Can't parse AAA servers for realm %s.", idp->realm_id->buf);
    tr_free_name(idp->realm_id);
    return NULL;
  }

  if ((NULL != (japcs = json_object_get(jidp, "apcs"))) &&
      (json_is_array(japcs))) {
    if (NULL == (idp->apcs = tr_cfg_parse_apcs(trc, japcs, rc))) {
      tr_debug("tr_cfg_parse_one_idp_realm: Can't parse APCs for realm %s .", idp->realm_id->buf);
      tr_free_name(idp->realm_id);
      /* TBD -- free aaa_servers */;
      return NULL;
    }
  } 
  return idp;
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

static TR_CFG_RC tr_cfg_parse_idp_realms (TR_CFG *trc, json_t *jcfg) 
{
  json_t *jidps = NULL;
  TR_CFG_RC rc = TR_CFG_SUCCESS;
  TR_IDP_REALM *idp = NULL;
  int i = 0;

  if ((!trc) || (!jcfg))
    return TR_CFG_BAD_PARAMS;

  /* If there are any IDP Realms, parse them */
  if ((NULL != (jidps = json_object_get(jcfg, "idp_realms"))) &&
      (json_is_array(jidps))) {
    for (i = 0; i < json_array_size(jidps); i++) {
      if (NULL == (idp = tr_cfg_parse_one_idp_realm(trc,
						    json_array_get(jidps, i), 
						    &rc))) {
	return rc;
      }
      tr_debug("tr_cfg_parse_idp_realms: IDP realm configured: %s.", idp->realm_id->buf);
      idp->next = trc->idp_realms;
      trc->idp_realms = idp;
    }
  }

  tr_debug("tr_cfg_parse_idp_realms: Finished (rc=%d)", rc);
  return rc;
}

static TR_IDP_REALM *tr_cfg_parse_comm_idps (TR_CFG *trc, json_t *jidps, TR_CFG_RC *rc)
{
  TR_IDP_REALM *idp = NULL;
  TR_IDP_REALM *temp_idp = NULL;
  int i = 0;

  if ((!trc) ||
      (!jidps) ||
      (!json_is_array(jidps))) {
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  for (i = 0; i < json_array_size(jidps); i++) {
    if (NULL == (temp_idp = (tr_cfg_find_idp(trc, 
                                             tr_new_name((char *)json_string_value(json_array_get(jidps, i))), 
                                             rc)))) {
      tr_debug("tr_cfg_parse_comm_idps: Unknown IDP %s.", 
	      (char *)json_string_value(json_array_get(jidps, i)));
      return NULL;
    }

    temp_idp->comm_next = idp;
    idp = temp_idp;
  }

  return idp;
}

static TR_RP_REALM *tr_cfg_parse_comm_rps (TR_CFG *trc, json_t *jrps, TR_CFG_RC *rc)
{
  TR_RP_REALM *rp = NULL;
  TR_RP_REALM *temp_rp = NULL;
  int i = 0;

  if ((!trc) ||
      (!jrps) ||
      (!json_is_array(jrps))) {
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  for (i = (json_array_size(jrps)-1); i >= 0; i--) {
    if (NULL == (temp_rp = talloc_zero(trc, TR_RP_REALM))) {
      tr_debug("tr_cfg_parse_comm_rps: Can't allocate memory for RP Realm.");
      if (rc)
	*rc = TR_CFG_NOMEM;
      return NULL;
    }

    if (NULL == (temp_rp->realm_name = tr_new_name((char *)json_string_value(json_array_get(jrps, i))))) {
      tr_debug("tr_cfg_parse_comm_rps: No memory for RP Realm Name.");
      if (rc)
	*rc = TR_CFG_NOMEM;
      return NULL;
    }

    temp_rp->next = rp;
    rp = temp_rp;
  }

  return rp;
}

static TR_COMM *tr_cfg_parse_one_comm (TR_CFG *trc, json_t *jcomm, TR_CFG_RC *rc) {
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
    return NULL;
  }

  if (NULL == (comm = talloc_zero(trc, TR_COMM))) {
    tr_crit("tr_cfg_parse_one_comm: Out of memory.");
    *rc = TR_CFG_NOMEM;
    return NULL;
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
    return NULL;
  }

  if (NULL == (comm->id = tr_new_name((char *)json_string_value(jid)))) {
    tr_debug("tr_cfg_parse_one_comm: No memory for community id.");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  if (0 == strcmp(json_string_value(jtype), "apc")) {
    comm->type = TR_COMM_APC;
  } else if (0 == strcmp(json_string_value(jtype), "coi")) {
    comm->type = TR_COMM_COI;
    if (NULL == (comm->apcs = tr_cfg_parse_apcs(trc, japcs, rc))) {
      tr_debug("tr_cfg_parse_one_comm: Can't parse APCs for COI %s.", comm->id->buf);
      tr_free_name(comm->id);
      return NULL;
    }
  } else {
    tr_debug("tr_cfg_parse_one_comm: Invalid community type, comm = %s, type = %s", comm->id->buf, json_string_value(jtype));
    tr_free_name(comm->id);
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  comm->idp_realms = tr_cfg_parse_comm_idps(trc, jidps, rc);
  if (TR_CFG_SUCCESS != *rc) {
    tr_debug("tr_cfg_parse_one_comm: Can't parse IDP realms for comm %s.", comm->id->buf);
    tr_free_name(comm->id);
    return NULL;
  }

  comm->rp_realms = tr_cfg_parse_comm_rps(trc, jrps, rc);
  if (TR_CFG_SUCCESS != *rc) {
    tr_debug("tr_cfg_parse_comm: Can't parse RP realms for comm %s .", comm->id->buf);
    tr_free_name(comm->id);
    return NULL;
  }

  if (TR_COMM_APC == comm->type) {
    json_t *jexpire  = json_object_get(jcomm, "expiration_interval");
    comm->expiration_interval = 43200; /*30 days*/
    if (jexpire) {
	if (!json_is_integer(jexpire)) {
	  fprintf(stderr, "tr_parse_comm: expirae_interval is not an integer\n");
	  return NULL;
	}
	comm->expiration_interval = json_integer_value(jexpire);
	if (comm->expiration_interval <= 10)
	  comm->expiration_interval = 11; /* Freeradius waits 10 minutes between successful TR queries*/
	if (comm->expiration_interval > 129600) /* 90 days*/
	comm->expiration_interval = 129600;
    }
  }
  
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
      if (NULL == (comm = tr_cfg_parse_one_comm(trc, 
						json_array_get(jcomms, i), 
						&rc))) {
	return rc;
      }
      tr_debug("tr_cfg_parse_comms: Community configured: %s.", comm->id->buf);
      comm->next = trc->comms;
      trc->comms = comm;
    }
  }
  tr_debug("tr_cfg_parse_comms: Finished (rc=%d)", rc);
  return rc;
}

TR_CFG_RC tr_cfg_validate (TR_CFG *trc) {
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
static char *join_paths(TALLOC_CTX *mem_ctx, const char *p1, const char *p2) {
  return talloc_asprintf(mem_ctx, "%s/%s", p1, p2); /* returns NULL on a failure */
}

/* Reads configuration files in config_dir ("" or "./" will use the current directory). */
TR_CFG_RC tr_parse_config (TR_CFG_MGR *cfg_mgr, const char *config_dir, int n, struct dirent **cfg_files)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  json_t *jcfg;
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
    if (NULL == (jcfg = json_load_file(file_with_path, 
                                       JSON_DISABLE_EOF_CHECK, &rc))) {
      tr_debug("tr_parse_config: Error parsing config file %s.", 
               cfg_files[ii]->d_name);
      cfg_rc=TR_CFG_NOPARSE;
      goto cleanup;
    }

    if ((TR_CFG_SUCCESS != tr_cfg_parse_internal(cfg_mgr->new, jcfg)) ||
        (TR_CFG_SUCCESS != tr_cfg_parse_rp_clients(cfg_mgr->new, jcfg)) ||
        (TR_CFG_SUCCESS != tr_cfg_parse_idp_realms(cfg_mgr->new, jcfg)) ||
        (TR_CFG_SUCCESS != tr_cfg_parse_default_servers(cfg_mgr->new, jcfg)) ||
        (TR_CFG_SUCCESS != tr_cfg_parse_comms(cfg_mgr->new, jcfg))) {
      cfg_rc=TR_CFG_ERROR;
      goto cleanup;
    }
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
