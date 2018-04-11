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


#ifndef TRUST_ROUTER_TR_MON_REQ_H
#define TRUST_ROUTER_TR_MON_REQ_H

#include <talloc.h>
#include <jansson.h>
#include <gmodule.h>

/* Typedefs */
typedef struct tr_mon_req TR_MON_REQ;

typedef enum tr_mon_cmd TR_MON_CMD;

typedef struct tr_mon_opt TR_MON_OPT;
typedef enum tr_mon_opt_type TR_MON_OPT_TYPE;

typedef enum tr_mon_rc TR_MON_RC;


/* Struct and enum definitions */
enum tr_mon_rc {
  TR_MON_SUCCESS=0,
  TR_MON_ERROR, /* generic error */
  TR_MON_BADARG, /* problem with the arguments */
  TR_MON_NOMEM, /* out of memory */
  TR_MON_NOPARSE, /* parsing failed */
};

enum tr_mon_cmd {
  MON_CMD_UNKNOWN=0,
  MON_CMD_RECONFIGURE,
  MON_CMD_SHOW
};

enum tr_mon_opt_type {
  OPT_TYPE_UNKNOWN=0,

  // System information
  OPT_TYPE_SHOW_VERSION,
  OPT_TYPE_SHOW_SERIAL,

  // System statistics
  OPT_TYPE_SHOW_UPTIME,
  OPT_TYPE_SHOW_TID_REQ_COUNT,
  OPT_TYPE_SHOW_TID_REQ_PENDING,

  // Dynamic trust router state
  OPT_TYPE_SHOW_ROUTES,
  OPT_TYPE_SHOW_COMMUNITIES
};

struct tr_mon_opt {
  TR_MON_OPT_TYPE type;
};

struct tr_mon_req {
  TR_MON_CMD command;
  GArray *options;
};

/* Prototypes */
TR_MON_REQ *tr_mon_req_new(TALLOC_CTX *mem_ctx, TR_MON_CMD cmd);
void tr_mon_req_free(TR_MON_REQ *req);
TR_MON_RC tr_mon_req_add_option(TR_MON_REQ *req, TR_MON_OPT_TYPE opt_type);
size_t tr_mon_req_opt_count(TR_MON_REQ *req);
TR_MON_OPT *tr_mon_req_opt_index(TR_MON_REQ *req, size_t index);

const char *cmd_to_string(TR_MON_CMD cmd);
TR_MON_CMD cmd_from_string(const char *s);

const char *opt_type_to_string(TR_MON_OPT_TYPE opt_type);
TR_MON_OPT_TYPE opt_type_from_string(const char *s);

/* tr_mon_req_encode.c */
json_t *tr_mon_req_encode(TR_MON_REQ *req);

/* tr_mon_req_decode.c */
TR_MON_REQ *tr_mon_req_decode(TALLOC_CTX *mem_ctx, const char *req_json);

/* tr_mon_rec_decode.c */

#endif //TRUST_ROUTER_TR_MON_REQ_H
