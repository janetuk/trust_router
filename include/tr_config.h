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

#include <tr.h>
#include <tr_rp.h>
#include <tr_idp.h>
#include <tr_comm.h>

#define TR_DEFAULT_MAX_TREE_DEPTH 12
#define TR_DEFAULT_TR_PORT 12308
#define TR_DEFAULT_TIDS_PORT 12309

typedef enum tr_cfg_rc {
  TR_CFG_SUCCESS = 0,	/* No error */
  TR_CFG_ERROR,		/* General processing error */
  TR_CFG_BAD_PARAMS,	/* Bad parameters passed to tr_config function */
  TR_CFG_NOPARSE,	/* Parsing error */
  TR_CFG_NOMEM		/* Memory allocation error */
} TR_CFG_RC;

typedef struct tr_cfg_internal {
  unsigned int max_tree_depth;
  unsigned int tids_port;
  const char *hostname;
} TR_CFG_INTERNAL;

typedef struct tr_cfg {
  TR_CFG_INTERNAL *internal;		/* internal trust router config */
  TR_IDP_REALM *idp_realms;		/* locally associated IDP Realms */
  TR_RP_CLIENT *rp_clients;		/* locally associated RP Clients */
  TR_COMM *comms;			/* locally-known communities */
  TR_AAA_SERVER *default_servers;	/* default server list */
  /* TBD -- Global Filters */
  /* TBD -- Trust Router Peers */
  /* TBD -- Trust Links */
} TR_CFG;

int tr_find_config_files (struct dirent ***cfg_files);
TR_CFG_RC tr_parse_config (TR_INSTANCE *tr, int n, struct dirent **cfg_files);
TR_CFG_RC tr_apply_new_config (TR_INSTANCE *tr);
TR_CFG_RC tr_cfg_validate (TR_CFG *trc);
void tr_cfg_free(TR_CFG *cfg);
void tr_print_config(FILE *stream, TR_CFG *cfg);

TR_IDP_REALM *tr_cfg_find_idp (TR_CFG *tr_cfg, TR_NAME *idp_id, TR_CFG_RC *rc);
TR_RP_CLIENT *tr_cfg_find_rp (TR_CFG *tr_cfg, TR_NAME *rp_gss, TR_CFG_RC *rc);
TR_RP_CLIENT *tr_rp_client_lookup(TR_INSTANCE *tr, TR_NAME *gss_name);

#endif
