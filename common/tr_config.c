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

#include <tr_config.h>
#include <tr.h>

void tr_print_config (FILE *stream, TR_CFG *cfg) {
  fprintf(stream, "tr_print_config: Not yet implemented.\n");
  return;
}

void tr_cfg_free (TR_CFG *cfg) {
  /* TBD -- need to deallocate memory as part of dynamic config */
  return;
}

TR_CFG_RC tr_apply_new_config (TR_INSTANCE *tr) {

  if (!tr)
    return TR_CFG_BAD_PARAMS;

  if (tr->active_cfg)
    tr_cfg_free(tr->active_cfg);

  tr->active_cfg = tr->new_cfg;
  return TR_CFG_SUCCESS;
}

static TR_CFG_RC tr_cfg_parse_internal (TR_INSTANCE *tr, json_t *jcfg) {
  json_t *jint = NULL;
  json_t *jmtd = NULL;

  if ((!tr) || (!tr->new_cfg) || (!jcfg))
    return TR_CFG_BAD_PARAMS;

  if (NULL == (tr->new_cfg->internal = malloc(sizeof(TR_CFG_INTERNAL))))
    return TR_CFG_NOMEM;

  memset(tr->new_cfg->internal, 0, sizeof(TR_CFG_INTERNAL));

  if ((NULL != (jint = json_object_get(jcfg, "tr_internal"))) &&
      (NULL != (jmtd = json_object_get(jint, "max_tree_depth")))) {
    if (json_is_number(jmtd)) {
      tr->new_cfg->internal->max_tree_depth = json_integer_value(jmtd);
    } else {
      fprintf(stderr,"tr_cfg_parse_internal: Parsing error, max_tree_depth is not a number.\n");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* If not configured, use the default */
    tr->new_cfg->internal->max_tree_depth = TR_DEFAULT_MAX_TREE_DEPTH;
  }
  fprintf(stderr, "tr_cfg_parse_internal: Internal config parsed.\n");
  return TR_CFG_SUCCESS;
}

static TR_CFG_RC tr_cfg_parse_rp_clients (TR_INSTANCE *tr, json_t *jcfg) {
  //  json_t *jrpr = NULL;
  
  return TR_CFG_SUCCESS;
}

static TR_AAA_SERVER *tr_cfg_parse_one_aaa_server (TR_INSTANCE *tr, json_t *jaddr, TR_CFG_RC *rc) {
  TR_AAA_SERVER *aaa = NULL;

  if ((!tr) || (!tr->new_cfg) || (!jaddr) || (!json_is_string(jaddr))) {
    fprintf(stderr, "tr_cfg_parse_one_aaa_server: Bad parameters.\n");
    *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  if (NULL == (aaa = malloc(sizeof(TR_AAA_SERVER)))) {
    fprintf(stderr, "tr_config_parse_one_aaa_server: Out of memory.\n");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  memset(aaa, 0, sizeof(TR_AAA_SERVER));

  /* TBD -- Handle IPv6 addresses */
  inet_aton(json_string_value(jaddr), &(aaa->aaa_server_addr));

  return aaa;
}


static TR_AAA_SERVER *tr_cfg_parse_aaa_servers (TR_INSTANCE *tr, json_t *jaaas, TR_CFG_RC *rc) 
{
  TR_AAA_SERVER *aaa = NULL;
  TR_AAA_SERVER *temp_aaa = NULL;
  int i = 0;

  for (i = 0; i < json_array_size(jaaas); i++) {
    if (NULL == (temp_aaa = tr_cfg_parse_one_aaa_server(tr, json_array_get(jaaas, i), rc))) {
      return NULL;
    }
    /* TBD -- IPv6 addresses */
    //    fprintf(stderr, "tr_cfg_parse_aaa_servers: Configuring AAA Server: ip_addr = %s.\n", inet_ntoa(temp_aaa->aaa_server_addr));
    temp_aaa->next = aaa;
    aaa = temp_aaa;
  }
  return aaa;
}

static TR_APC *tr_cfg_parse_apcs (TR_INSTANCE *tr, json_t *japcs, TR_CFG_RC *rc)
{
  TR_APC *apc;

  *rc = TR_CFG_SUCCESS;		/* presume success */

  if ((!japcs) || (!rc)) {
    fprintf(stderr, "tr_cfg_parse_apcs: Bad parameters.\n");
    if (rc) 
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  if (NULL == (apc = malloc(sizeof(TR_APC)))) {
    fprintf (stderr, "tr_cfg_parse_apcs: Out of memory.\n");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  memset(apc, 0, sizeof(TR_APC));

  /* TBD, deal with more than one APC.  In the meantime, though...                */
  /* Only parse the first APC, because we only know how to deal with one, anyway. */
  if (0 == json_array_size(japcs))
    return NULL;

  if (NULL == (apc->id = tr_new_name((char *)json_string_value(json_array_get(japcs, 0))))) {
    fprintf(stderr, "tr_cfg_parse_apcs: No memory for APC name.\n");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  return apc;
}

static TR_IDP_REALM *tr_cfg_parse_one_idp_realm (TR_INSTANCE *tr, json_t *jidp, TR_CFG_RC *rc) {
  TR_IDP_REALM *idp = NULL;
  json_t *jrid = NULL;
  json_t *jscfg = NULL;
  json_t *jsrvrs = NULL;
  json_t *japcs = NULL;

  if ((!jidp) || (!rc)) {
    fprintf(stderr, "tr_cfg_parse_one_idp_realm: Bad parameters.\n");
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  if (NULL == (idp = malloc(sizeof(TR_IDP_REALM)))) {
    fprintf(stderr, "tr_config_parse_one_idp_realm: Out of memory.\n");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  memset(idp, 0, sizeof(TR_IDP_REALM));

  if ((NULL == (jrid = json_object_get(jidp, "realm_id"))) ||
      (!json_is_string(jrid)) ||
      (NULL == (jscfg = json_object_get(jidp, "shared_config"))) ||
      (!json_is_string(jscfg)) ||
      (NULL == (jsrvrs = json_object_get(jidp, "aaa_servers"))) ||
      (!json_is_array(jsrvrs)) ||
      (NULL == (japcs = json_object_get(jidp, "apcs"))) ||
      (!json_is_array(japcs))) {
    fprintf(stderr, "tr_cfg_parse_one_idp_realm: Error parsing IDP realm configuration.\n");
    free(idp);
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  if (0 == strcmp(json_string_value(jscfg), "no")) {
    idp->shared_config = 0;
  } else {
    idp->shared_config = 1;
  }

  if (NULL == (idp->realm_id = tr_new_name((char *)json_string_value(jrid)))) {
    free(idp);
    fprintf(stderr, "tr_cfg_parse_one_idp_realm: No memory for realm id.\n");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  if (NULL == (idp->aaa_servers = tr_cfg_parse_aaa_servers(tr, jsrvrs, rc))) {
    fprintf(stderr, "tr_cfg_parse_one_idp_realm: Can't parse AAA servers for realm %s.\n", idp->realm_id->buf);
    tr_free_name(idp->realm_id);
    free(idp);
    return NULL;
  }
  if (NULL == (idp->apcs = tr_cfg_parse_apcs(tr, japcs, rc))) {
    fprintf(stderr, "tr_cfg_parse_one_idp_realm: Can't parse APCs for realm %s .\n", idp->realm_id->buf);
    tr_free_name(idp->realm_id);
    /* TBD -- free aaa_servers */;
    free(idp);
    return NULL;
  }

return idp;
}

static TR_CFG_RC tr_cfg_parse_idp_realms (TR_INSTANCE *tr, json_t *jcfg) 
{
  json_t *jidps = NULL;
  TR_CFG_RC rc = TR_CFG_SUCCESS;
  TR_IDP_REALM *idp = NULL;
  int i = 0;

  if ((!tr) || (!tr->new_cfg) || (!jcfg))
    return TR_CFG_BAD_PARAMS;

  if ((NULL == (jidps = json_object_get(jcfg, "idp_realms"))) ||
      (!json_is_array(jidps))) {
    return TR_CFG_NOPARSE;
  }

  for (i = 0; i < json_array_size(jidps); i++) {
    if (NULL == (idp = tr_cfg_parse_one_idp_realm(tr, 
						  json_array_get(jidps, i), 
						  &rc))) {
       return rc;
    }
    fprintf(stderr, "tr_cfg_parse_idp_realms: IDP realm configured: %s.\n", idp->realm_id->buf);
    idp->next = tr->new_cfg->idp_realms;
    tr->new_cfg->idp_realms = idp;
  }
  return rc;
}

static TR_IDP_REALM *tr_cfg_parse_comm_idps (TR_INSTANCE *tr, json_t *idps, TR_CFG_RC *rc)
{
  TR_IDP_REALM *idp;

  return (idp = malloc(sizeof(TR_IDP_REALM)));
}

static TR_RP_REALM *tr_cfg_parse_comm_rps (TR_INSTANCE *tr, json_t *rps, TR_CFG_RC *rc)
{
  TR_RP_REALM *rp;

  return (rp = malloc(sizeof(TR_RP_REALM)));
}

static TR_COMM *tr_cfg_parse_one_comm (TR_INSTANCE *tr, json_t *jcomm, TR_CFG_RC *rc) {
  TR_COMM *comm = NULL;
  json_t *jid = NULL;
  json_t *jtype = NULL;
  json_t *japcs = NULL;
  json_t *jidps = NULL;
  json_t *jrps = NULL;

  if ((!jcomm) || (!rc)) {
    fprintf(stderr, "tr_cfg_parse_one_comm: Bad parameters.\n");
    if (rc)
      *rc = TR_CFG_BAD_PARAMS;
    return NULL;
  }

  if (NULL == (comm = malloc(sizeof(TR_COMM)))) {
    fprintf(stderr, "tr_config_parse_one_comm: Out of memory.\n");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  memset(comm, 0, sizeof(TR_COMM));

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
    fprintf(stderr, "tr_cfg_parse_one_comm: Error parsing Communities configuration.\n");
    free(comm);
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  if (NULL == (comm->id = tr_new_name((char *)json_string_value(jid)))) {
    free(comm);
    fprintf(stderr, "tr_cfg_parse_one_comm: No memory for community id.\n");
    *rc = TR_CFG_NOMEM;
    return NULL;
  }

  if (0 == strcmp(json_string_value(jtype), "apc")) {
    comm->type = TR_COMM_APC;
  } else if (0 == strcmp(json_string_value(jtype), "coi")) {
    comm->type = TR_COMM_COI;
    if (NULL == (comm->apcs = tr_cfg_parse_apcs(tr, japcs, rc))) {
      fprintf(stderr, "tr_cfg_parse_one_comm: Can't parse APCs for COI %s.\n", comm->id->buf);
      tr_free_name(comm->id);
      free(comm);
      return NULL;
    }
  } else {
    fprintf(stderr, "tr_cfg_parse_one_comm: Invalid community type, comm = %s, type = %s\n", comm->id->buf, json_string_value(jtype));
    tr_free_name(comm->id);
    free(comm);
    *rc = TR_CFG_NOPARSE;
    return NULL;
  }

  comm->idp_realms = tr_cfg_parse_comm_idps(tr, jidps, rc);
  if (TR_CFG_SUCCESS != *rc) {
    fprintf(stderr, "tr_cfg_parse_one_comm: Can't parse IDP realms for comm %s.\n", comm->id->buf);
    tr_free_name(comm->id);
    free(comm);
    return NULL;
  }

  comm->rp_realms = tr_cfg_parse_comm_rps(tr, jrps, rc);
  if (TR_CFG_SUCCESS != *rc) {
    fprintf(stderr, "tr_cfg_parse_comm: Can't parse RP realms for comm %s .\n", comm->id->buf);
    tr_free_name(comm->id);
    /* TBD -- free idps? */;
    free(comm);
    return NULL;
  }

  return comm;
}

static TR_CFG_RC tr_cfg_parse_comms (TR_INSTANCE *tr, json_t *jcfg) 
{
  json_t *jcomms = NULL;
  TR_CFG_RC rc = TR_CFG_SUCCESS;
  TR_COMM *comm = NULL;
  int i = 0;

  if ((!tr) || (!tr->new_cfg) || (!jcfg)) {
    fprintf(stderr, "tr_config_parse_comms: Bad Parameters.\n");
    return TR_CFG_BAD_PARAMS;
  }

  if (NULL == (comm = malloc(sizeof(TR_COMM)))) {
    fprintf(stderr, "tr_cfg_parse_comms: Out of Memory\n");
    return TR_CFG_NOMEM;
  }
  memset (comm, 0, sizeof(TR_COMM));

  if ((NULL == (jcomms = json_object_get(jcfg, "communities"))) ||
      (!json_is_array(jcomms))) {
    return TR_CFG_NOPARSE;
  }

  for (i = 0; i < json_array_size(jcomms); i++) {
    if (NULL == (comm = tr_cfg_parse_one_comm(tr, 
					      json_array_get(jcomms, i), 
					      &rc))) {
       return rc;
    }
    fprintf(stderr, "tr_cfg_parse_comms: Community configured: %s.\n", comm->id->buf);
    comm->next = tr->new_cfg->comms;
    tr->new_cfg->comms = comm;
  }
  return rc;
}

TR_CFG_RC tr_parse_config (TR_INSTANCE *tr, json_t *jcfg) {

  /* If there is a partial/abandoned config lying around, free it */
  if (tr->new_cfg) {
    tr_cfg_free(tr->new_cfg);
  }
  
  if (NULL == (tr->new_cfg = malloc(sizeof(TR_CFG))))
    return TR_CFG_NOMEM;

  memset(tr->new_cfg, 0, sizeof(TR_CFG));

  if ((TR_CFG_SUCCESS != tr_cfg_parse_internal(tr, jcfg)) ||
      (TR_CFG_SUCCESS != tr_cfg_parse_rp_clients(tr, jcfg)) ||
      (TR_CFG_SUCCESS != tr_cfg_parse_idp_realms(tr, jcfg)) ||
      (TR_CFG_SUCCESS != tr_cfg_parse_comms(tr, jcfg))) {
    tr_cfg_free(tr->new_cfg);
    return TR_CFG_ERROR;
  }
  return TR_CFG_SUCCESS;
}

json_t *tr_read_config (int n, struct dirent **cfg_files) {
  json_t *jcfg = NULL;
  json_t *temp = NULL;
  json_error_t err;

  if (!cfg_files)
    return NULL;

  while (n--) {
    fprintf(stderr, "tr_read_config: Parsing %s.\n", cfg_files[n]->d_name);
    if (NULL == (temp = json_load_file(cfg_files[n]->d_name, JSON_DISABLE_EOF_CHECK, &err))) {
      fprintf (stderr, "tr_read_config: Error parsing config file %s.\n", cfg_files[n]->d_name);
      return NULL;
    }

    if (!jcfg) {
      jcfg = temp;
    }else {
      if (-1 == json_object_update(jcfg, temp)) {
	fprintf(stderr, "tr_read_config: Error merging config information.\n");
	return NULL;
      }
    }
  }

  //  fprintf(stderr, "tr_read_config: Merged configuration complete:\n%s\n", json_dumps(jcfg, 0));

  return jcfg;
}

static int is_cfg_file(const struct dirent *dent) {
  int n;

  /* if the last four letters of the filename are .cfg, return true. */
  if ((4 <= (n = strlen(dent->d_name))) &&
      (0 == strcmp(&(dent->d_name[n-4]), ".cfg"))) {
    return 1;
  }

  /* otherwise, return false. */
  return 0;
}

int tr_find_config_files (struct dirent ***cfg_files) {
  int n = 0, i = 0;
  
  n = scandir(".", cfg_files, &is_cfg_file, 0);

  if (n < 0) {
    perror("scandir");
    fprintf(stderr, "tr_find_config: scandir error.\n");
    return 0;
  }

  if (n == 0) {
    fprintf (stderr, "tr_find_config: No config files found.\n");
    return 0;
  }

  i = n;
  while(i--) {
    fprintf(stderr, "tr_find_config: Config file found (%s).\n", (*cfg_files)[i]->d_name);
  }
    
  return n;
}
