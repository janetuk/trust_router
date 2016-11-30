/*
 * Copyright (c) 2012-2015, JANET(UK)
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

#ifndef TID_INTERNAL_H
#define TID_INTERNAL_H
#include <glib.h>

#include <tr_rp.h>
#include <trust_router/tid.h>
#include <jansson.h>

struct tid_srvr_blk {
  TID_SRVR_BLK *next;
  char *aaa_server_addr;
  TR_NAME *key_name;
  DH *aaa_server_dh;		/* AAA server's public dh information */
  GTimeVal key_expiration; /**< absolute time at which key expires*/
  json_t *path;/**< Path of trust routers that the request traversed*/
};

struct tid_resp {
  TID_RC result;
  TR_NAME *err_msg;
  TR_NAME *rp_realm;
  TR_NAME *realm;
  TR_NAME *comm;
  TR_CONSTRAINT_SET *cons;
  TR_NAME *orig_coi;
  TID_SRVR_BLK *servers;       	/* array of servers */
  json_t *error_path; /**< Path that a request generating an error traveled*/
};

struct tid_req {
  struct tid_req *next_req;
  int resp_sent;
  int conn;
  int free_conn; /* free conn and gss ctx*/
  gss_ctx_id_t gssctx;
  int resp_rcvd;
  TR_NAME *rp_realm;
  TR_NAME *realm;
  TR_NAME *comm;
  TR_CONSTRAINT_SET *cons;
  TR_NAME *orig_coi;
  DH *tidc_dh;			/* Client's public dh information */
  TIDC_RESP_FUNC *resp_func;
  void *cookie;
  time_t expiration_interval; /**< Time to key expire in minutes*/
  json_t *json_references; /**< References to objects dereferenced on request destruction*/
  json_t *path; /**< Path of systems this request has traversed; added by receiver*/
};

struct tidc_instance {
  // TID_REQ *req_list;
  // TBD -- Do we still need a separate private key */
  // char *priv_key;
  // int priv_len;
  DH *client_dh;			/* Client's DH struct with priv and pub keys */
};

struct tids_instance {
  int req_count;
  char *priv_key;
  char *ipaddr;
  const char *hostname;
  TIDS_REQ_FUNC *req_handler;
  TIDS_AUTH_FUNC *auth_handler;
  void *cookie;
  uint16_t tids_port;
  struct tr_rp_client *rp_gss;		/* Client matching GSS name */
};

/** Decrement a reference to #json when this tid_req is cleaned up. A
    new reference is not created; in effect the caller is handing a
    reference they already hold to the TID_REQ.*/
void tid_req_cleanup_json(TID_REQ *, json_t *json);

int tid_req_add_path(TID_REQ *, const char *this_system, unsigned port);

TID_SRVR_BLK *tid_srvr_blk_new(TALLOC_CTX *mem_ctx);
void tid_srvr_blk_free(TID_SRVR_BLK *srvr);
TID_SRVR_BLK *tid_srvr_blk_dup(TALLOC_CTX *mem_ctx, TID_SRVR_BLK *srvr);
TID_SRVR_BLK *tid_srvr_blk_add_func(TID_SRVR_BLK *head, TID_SRVR_BLK *new);
#define tid_srvr_blk_add(head, new) ((head)=tid_srvr_blk_add_func((head),(new)))
void tid_srvr_blk_set_path(TID_SRVR_BLK *block, json_t *path);

void tid_resp_set_cons(TID_RESP *resp, TR_CONSTRAINT_SET *cons);
void tid_resp_set_error_path(TID_RESP *resp, json_t *ep);

#endif
