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

#ifndef TID_H
#define TID_H

#include <arpa/inet.h>
#include <openssl/dh.h>

#include <trust_router/tr_name.h>
#include <trust_router/tr_versioning.h>

#define TID_PORT	12309

typedef struct gss_ctx_id_struct *gss_ctx_id_t;

typedef enum tid_rc {
  TID_SUCCESS = 0,
  TID_ERROR
} TID_RC;

typedef struct tid_srvr_blk {
  struct tid_srvr_blk *next;
  struct in_addr aaa_server_addr;
  TR_NAME *key_name;
  DH *aaa_server_dh;		/* AAA server's public dh information */
} TID_SRVR_BLK;
  
typedef struct tid_resp {
  TID_RC result;
  TR_NAME *err_msg;
  TR_NAME *rp_realm;
  TR_NAME *realm;
  TR_NAME *comm;
  TR_NAME *orig_coi;
  TID_SRVR_BLK *servers;       	/* Linked list of servers */
  /* TBD -- Trust Path Used */
} TID_RESP;

typedef struct tidc_instance TIDC_INSTANCE;
typedef struct tids_instance TIDS_INSTANCE;
typedef struct tid_req TID_REQ;

typedef void (TIDC_RESP_FUNC)(TIDC_INSTANCE *, TID_REQ *, TID_RESP *, void *);

struct tid_req {
  struct tid_req *next_req;
  int conn;
  gss_ctx_id_t gssctx;
  int resp_rcvd;
  TR_NAME *rp_realm;
  TR_NAME *realm;
  TR_NAME *comm;
  TR_NAME *orig_coi;
  DH *tidc_dh;			/* Client's public dh information */
  TIDC_RESP_FUNC *resp_func;
  void *cookie;
};

struct tidc_instance {
  TID_REQ *req_list;
  // TBD -- Do we still need a separate private key */
  // char *priv_key;
  // int priv_len;
  DH *client_dh;			/* Client's DH struct with priv and pub keys */
};

typedef int (TIDS_REQ_FUNC)(TIDS_INSTANCE *, TID_REQ *, TID_RESP **, void *);

struct tids_instance {
  int req_count;
  char *priv_key;
  char *ipaddr;
  TIDS_REQ_FUNC *req_handler;
  void *cookie;
};

TR_EXPORT TIDC_INSTANCE *tidc_create (void);
TR_EXPORT int tidc_open_connection (TIDC_INSTANCE *tidc, char *server, gss_ctx_id_t *gssctx);
TR_EXPORT int tidc_send_request (TIDC_INSTANCE *tidc, int conn, gss_ctx_id_t gssctx, char *rp_realm, char *realm, char *coi, TIDC_RESP_FUNC *resp_handler, void *cookie);
TR_EXPORT int tids_send_response (TIDS_INSTANCE *tids, int conn, gss_ctx_id_t *gssctx, TID_RESP *resp);
TR_EXPORT void tidc_destroy (TIDC_INSTANCE *tidc);

TR_EXPORT TIDS_INSTANCE *tids_create (void);
TR_EXPORT int tids_start (TIDS_INSTANCE *tids, TIDS_REQ_FUNC *req_handler, void *cookie);
TR_EXPORT void tids_destroy (TIDS_INSTANCE *tids);

#endif
