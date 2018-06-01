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

#ifndef TR_CONFIG_H
#define TR_CONFIG_H

#include <stdio.h>
#include <dirent.h>
#include <jansson.h>
#include <syslog.h>
#include <sys/time.h>
#include <talloc.h>
#include <glib.h>

#include <tr_comm.h>
#include <tr_rp.h>
#include <tr_rp_client.h>
#include <tr_idp.h>
#include <trp_ptable.h>
#include <trp_internal.h>

#define TR_DEFAULT_MAX_TREE_DEPTH 12
#define TR_DEFAULT_TRPS_PORT 12308
#define TR_DEFAULT_TIDS_PORT 12309
#define TR_DEFAULT_MONITORING_PORT 0 /* defaults to being turned off */
#define TR_DEFAULT_LOG_THRESHOLD LOG_INFO
#define TR_DEFAULT_CONSOLE_THRESHOLD LOG_NOTICE
#define TR_DEFAULT_APC_EXPIRATION_INTERVAL 43200
#define TR_DEFAULT_TRP_CONNECT_INTERVAL 10
#define TR_DEFAULT_TRP_UPDATE_INTERVAL 30
#define TR_DEFAULT_TRP_SWEEP_INTERVAL 30
#define TR_DEFAULT_TID_REQ_TIMEOUT 5
#define TR_DEFAULT_TID_RESP_NUMER 2
#define TR_DEFAULT_TID_RESP_DENOM 3

/* limits on values for validations */
#define TR_MIN_TRP_CONNECT_INTERVAL 5
#define TR_MIN_TRP_SWEEP_INTERVAL 5
#define TR_MIN_TRP_UPDATE_INTERVAL 5
#define TR_MIN_CFG_POLL_INTERVAL 1
#define TR_MIN_CFG_SETTLING_TIME 0
#define TR_MIN_TID_REQ_TIMEOUT 1

#define TR_CFG_INVALID_SERIAL -1

typedef enum tr_cfg_rc {
  TR_CFG_SUCCESS = 0,	/* No error */
  TR_CFG_ERROR,		/* General processing error */
  TR_CFG_BAD_PARAMS,	/* Bad parameters passed to tr_config function */
  TR_CFG_NOPARSE,	/* Parsing error */
  TR_CFG_NOMEM,		/* Memory allocation error */
} TR_CFG_RC;

typedef struct tr_cfg_internal {
  unsigned int max_tree_depth;
  int tids_port;
  int trps_port;
  int mons_port;
  const char *hostname;
  int log_threshold;
  int console_threshold;
  unsigned int cfg_poll_interval;
  unsigned int cfg_settling_time;
  unsigned int trp_sweep_interval;
  unsigned int trp_update_interval;
  unsigned int trp_connect_interval;
  unsigned int tid_req_timeout;
  unsigned int tid_resp_numer; /* numerator of fraction of AAA servers to wait for in unshared mode */
  unsigned int tid_resp_denom; /* denominator of fraction of AAA servers to wait for in unshared mode */
  TR_GSS_NAMES *monitoring_credentials;
} TR_CFG_INTERNAL;

/* record of files loaded for this configuration */
typedef struct tr_cfg_file {
  const char *name;
  json_int_t serial;
} TR_CFG_FILE;

typedef struct tr_cfg {
  TR_CFG_INTERNAL *internal;		/* internal trust router config */
  TR_RP_CLIENT *rp_clients;		/* locally associated RP Clients */
  TRP_PTABLE *peers; /* TRP peer table */
  TR_COMM_TABLE *ctable; /* communities/realms */
  TR_AAA_SERVER *default_servers;	/* default server list */

  GArray *files; /* files loaded to make this configuration */
} TR_CFG;

typedef struct tr_cfg_mgr {
  TR_CFG *active;
  TR_CFG *new;
} TR_CFG_MGR;

int tr_find_config_files(const char *config_dir, struct dirent ***cfg_files);
void tr_free_config_file_list(int n, struct dirent ***cfg_files);
TR_CFG_RC tr_parse_config(TR_CFG_MGR *cfg_mgr, unsigned int n_files, char **files_with_paths);
TR_CFG_RC tr_apply_new_config (TR_CFG_MGR *cfg_mgr);
TR_CFG_RC tr_cfg_validate (TR_CFG *trc);
TR_CFG *tr_cfg_new(TALLOC_CTX *mem_ctx);
TR_CFG_MGR *tr_cfg_mgr_new(TALLOC_CTX *mem_ctx);
void tr_cfg_free(TR_CFG *cfg);
void tr_cfg_mgr_free(TR_CFG_MGR *cfg);

void tr_print_config(TR_CFG *cfg);
void tr_print_comms(TR_COMM_TABLE *ctab);
void tr_print_comm_idps(TR_COMM_TABLE *ctab, TR_COMM *comm);
void tr_print_comm_rps(TR_COMM_TABLE *ctab, TR_COMM *comm);

/* tr_config_internal.c */
TR_CFG_RC tr_cfg_parse_internal(TR_CFG *trc, json_t *jint);
TR_CFG_RC tr_cfg_validate_internal(TR_CFG_INTERNAL *int_cfg);

/* tr_config_comms.c */
TR_IDP_REALM *tr_cfg_find_idp (TR_CFG *tr_cfg, TR_NAME *idp_id, TR_CFG_RC *rc);
TR_RP_CLIENT *tr_cfg_find_rp (TR_CFG *tr_cfg, TR_NAME *rp_gss, TR_CFG_RC *rc);
TR_CFG_RC tr_cfg_parse_comms (TR_CFG *trc, json_t *jcfg);
TR_CFG_RC tr_cfg_parse_default_servers (TR_CFG *trc, json_t *jcfg);

/* tr_config_filters.c */
TR_FILTER_SET *tr_cfg_parse_filters(TALLOC_CTX *mem_ctx, json_t *jfilts, TR_CFG_RC *rc);

/* tr_config_orgs.c */
TR_CFG_RC tr_cfg_parse_local_orgs(TR_CFG *trc, json_t *jcfg);
TR_CFG_RC tr_cfg_parse_peer_orgs(TR_CFG *trc, json_t *jcfg);

/* tr_config_realms.c */
TR_IDP_REALM *tr_cfg_parse_idp_realms(TALLOC_CTX *mem_ctx, json_t *jrealms, TR_CFG_RC *rc);
TR_AAA_SERVER *tr_cfg_parse_one_aaa_server(TALLOC_CTX *mem_ctx, json_t *jaddr, TR_CFG_RC *rc);
TR_APC *tr_cfg_parse_apcs(TALLOC_CTX *mem_ctx, json_t *japcs, TR_CFG_RC *rc);

/* tr_config_rp_clients.c */
TR_RP_CLIENT *tr_cfg_parse_rp_clients(TALLOC_CTX *mem_ctx, json_t *jrealms, TR_CFG_RC *rc);
TR_CFG_RC tr_cfg_parse_gss_names(TALLOC_CTX *mem_ctx, json_t *jgss_names, TR_GSS_NAMES **gssn_out);

/* tr_config_encoders.c */
json_t *tr_cfg_files_to_json_array(TR_CFG *cfg);

#endif
