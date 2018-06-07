/*
 * Copyright (c) 2018, JANET(UK)
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


#ifndef TRUST_ROUTER_MON_REQ_H
#define TRUST_ROUTER_MON_REQ_H

#include <talloc.h>
#include <stdint.h>
#include <jansson.h>
#include <glib.h>
#include <gssapi.h>
#include <trust_router/tid.h>
#include <trp_internal.h>
#include <tr_gss_names.h>
#include <tr_gss_client.h>
#include <tr_name_internal.h>
#include <mon.h>

/* Typedefs go in mon.h */

/* Struct and enum definitions */
enum mon_rc {
  MON_SUCCESS=0,
  MON_ERROR, /* generic error */
  MON_BADARG, /* problem with the arguments */
  MON_NOMEM, /* out of memory */
  MON_NOPARSE, /* parsing failed */
};

enum mon_cmd {
  MON_CMD_UNKNOWN=0,
  MON_CMD_SHOW
};

/* These should be explicitly numbered because they form part of the public API */
enum mon_resp_code {
  MON_RESP_SUCCESS=0,
  MON_RESP_ERROR=1, // generic error
};

enum mon_opt_type {
  OPT_TYPE_UNKNOWN=0,
  OPT_TYPE_ANY,

  // System information
  OPT_TYPE_SHOW_VERSION,
  OPT_TYPE_SHOW_CONFIG_FILES,

  // System statistics
  OPT_TYPE_SHOW_UPTIME,
  OPT_TYPE_SHOW_TID_REQS_PROCESSED,
  OPT_TYPE_SHOW_TID_REQS_FAILED,
  OPT_TYPE_SHOW_TID_ERROR_COUNT,
  OPT_TYPE_SHOW_TID_REQS_PENDING,

  // Dynamic trust router state
  OPT_TYPE_SHOW_ROUTES,
  OPT_TYPE_SHOW_PEERS,
  OPT_TYPE_SHOW_COMMUNITIES,
  OPT_TYPE_SHOW_REALMS,
  OPT_TYPE_SHOW_RP_CLIENTS
};

struct mon_opt {
  MON_OPT_TYPE type;
};

struct mon_req {
  MON_CMD command;
  GArray *options;
};

struct mon_resp {
  MON_RESP_CODE code;
  TR_NAME *message;
  json_t *payload;
};

/* Monitoring server instance */
struct mons_instance {
  const char *hostname;
  int mon_port;
  TR_GSS_NAMES *authorized_gss_names;
  TIDS_INSTANCE *tids;
  TRPS_INSTANCE *trps;
  MONS_REQ_FUNC *req_handler;
  MONS_AUTH_FUNC *auth_handler;
  void *cookie;
  GPtrArray *handlers;
  GArray *pids; /* PIDs of active mons processes */
};

/* Client instance */
struct monc_instance {
  TR_GSSC_INSTANCE *gssc;
};

/* Prototypes */
/* mon_common.c */
const char *mon_cmd_to_string(MON_CMD cmd);
MON_CMD mon_cmd_from_string(const char *s);
const char *mon_opt_type_to_string(MON_OPT_TYPE opt_type);
MON_OPT_TYPE mon_opt_type_from_string(const char *s);

/* mon_req.c */
MON_REQ *mon_req_new(TALLOC_CTX *mem_ctx, MON_CMD cmd);
void mon_req_free(MON_REQ *req);
MON_RC mon_req_add_option(MON_REQ *req, MON_OPT_TYPE opt_type);
size_t mon_req_opt_count(MON_REQ *req);
MON_OPT *mon_req_opt_index(MON_REQ *req, size_t index);

/* mon_req_encode.c */
json_t *mon_req_encode(MON_REQ *req);

/* mon_req_decode.c */
MON_REQ *mon_req_decode(TALLOC_CTX *mem_ctx, json_t *req_json);
MON_REQ *mon_req_parse(TALLOC_CTX *mem_ctx, const char *input);

/* mon_resp.c */
MON_RESP *mon_resp_new(TALLOC_CTX *mem_ctx, MON_RESP_CODE code, const char *msg, json_t *payload);
void mon_resp_free(MON_RESP *resp);
int mon_resp_set_message(MON_RESP *resp, const char *new_msg);
void mon_resp_set_payload(MON_RESP *resp, json_t *new_payload);

/* mon_resp_encode.c */
json_t *mon_resp_encode(MON_RESP *resp);

/* mon_resp_decode.c */
MON_RESP * mon_resp_decode(TALLOC_CTX *mem_ctx, json_t *resp_json);

/* mons.c */
MONS_INSTANCE *mons_new(TALLOC_CTX *mem_ctx);
int mons_get_listener(MONS_INSTANCE *mons,
                      MONS_REQ_FUNC *req_handler,
                      MONS_AUTH_FUNC *auth_handler,
                      const char *hostname,
                      int port,
                      void *cookie,
                      int *fd_out,
                      size_t max_fd);
int mons_accept(MONS_INSTANCE *mons, int listen);

/* monc.c */
MONC_INSTANCE *monc_new(TALLOC_CTX *mem_ctx);
void monc_free(MONC_INSTANCE *monc);
int monc_open_connection(MONC_INSTANCE *monc, const char *server, int port);
MON_RESP *monc_send_request(TALLOC_CTX *mem_ctx, MONC_INSTANCE *monc, MON_REQ *req);

#endif //TRUST_ROUTER_MON_REQ_H
