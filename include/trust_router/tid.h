/*
 * Copyright (c) 2012-2014, JANET(UK)
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

#include <talloc.h>

#include <arpa/inet.h>
#include <openssl/dh.h>

#include <trust_router/tr_name.h>
#include <trust_router/tr_versioning.h>

#include <gssapi.h>


#define TID_PORT	12309

typedef enum tid_rc {
  TID_SUCCESS = 0,
  TID_ERROR
} TID_RC;

typedef struct tid_srvr_blk  TID_SRVR_BLK;


typedef struct _tr_constraint_set  TR_CONSTRAINT_SET;
typedef struct _tid_path TID_PATH;

typedef struct tid_resp TID_RESP;

typedef struct tidc_instance TIDC_INSTANCE;
typedef struct tids_instance TIDS_INSTANCE;
typedef struct tid_req TID_REQ;


typedef void (TIDC_RESP_FUNC)(TIDC_INSTANCE *, TID_REQ *, TID_RESP *, void *);



typedef int (TIDS_REQ_FUNC)(TIDS_INSTANCE *, TID_REQ *, TID_RESP *, void *);
typedef int (tids_auth_func)(gss_name_t client_name, TR_NAME *display_name, void *cookie);



/* Utility functions for TID_REQ structures, in tid/tid_req.c */
TR_EXPORT TID_REQ *tid_req_new(void);
TR_EXPORT TID_REQ *tid_req_get_next_req(TID_REQ *req);
void tid_req_set_next_req(TID_REQ *req, TID_REQ *next_req);
TR_EXPORT int tid_req_get_resp_sent(TID_REQ *req);
void tid_req_set_resp_sent(TID_REQ *req, int resp_sent);
TR_EXPORT int tid_req_get_conn(TID_REQ *req);
void tid_req_set_conn(TID_REQ *req, int conn);
TR_EXPORT gss_ctx_id_t tid_req_get_gssctx(TID_REQ *req);
void tid_req_set_gssctx(TID_REQ *req, gss_ctx_id_t gssctx);
TR_EXPORT int tid_req_get_resp_rcvd(TID_REQ *req);
void tid_req_set_resp_rcvd(TID_REQ *req, int resp_rcvd);
TR_EXPORT TR_NAME *tid_req_get_rp_realm(TID_REQ *req);
void tid_req_set_rp_realm(TID_REQ *req, TR_NAME *rp_realm);
TR_EXPORT TR_NAME *tid_req_get_realm(TID_REQ *req);
void tid_req_set_realm(TID_REQ *req, TR_NAME *realm);
TR_EXPORT TR_NAME *tid_req_get_comm(TID_REQ *req);
void tid_req_set_comm(TID_REQ *req, TR_NAME *comm);
TR_EXPORT TR_NAME *tid_req_get_orig_coi(TID_REQ *req);
void tid_req_set_rp_orig_coi(TID_REQ *req, TR_NAME *orig_coi);
TR_EXPORT TIDC_RESP_FUNC *tid_req_get_resp_func(TID_REQ *req);
void tid_req_set_resp_func(TID_REQ *req, TIDC_RESP_FUNC *resp_func);
TR_EXPORT void *tid_req_get_cookie(TID_REQ *req);
void tid_req_set_cookie(TID_REQ *req, void *cookie);
TR_EXPORT TID_REQ *tid_dup_req (TID_REQ *orig_req);
TR_EXPORT void tid_req_free( TID_REQ *req);

/* Utility functions for TID_RESP structure, in tid/tid_resp.c */

TID_RESP *tid_resp_new(TALLOC_CTX *mem_ctx);
void tid_resp_free(TID_RESP *resp);
TID_RESP *tid_resp_dup(TALLOC_CTX *mem_ctx, TID_RESP *resp);
TR_EXPORT int tid_resp_get_result(TID_RESP *resp);
void tid_resp_set_result(TID_RESP *resp, int result);
TR_EXPORT TR_NAME *tid_resp_get_err_msg(TID_RESP *resp);
void tid_resp_set_err_msg(TID_RESP *resp, TR_NAME *err_msg);
TR_EXPORT TR_NAME *tid_resp_get_rp_realm(TID_RESP *resp);
void tid_resp_set_rp_realm(TID_RESP *resp, TR_NAME *rp_realm);
TR_EXPORT TR_NAME *tid_resp_get_realm(TID_RESP *resp);
void tid_resp_set_realm(TID_RESP *resp, TR_NAME *realm);
TR_EXPORT TR_NAME *tid_resp_get_comm(TID_RESP *resp);
void tid_resp_set_comm(TID_RESP *resp, TR_NAME *comm);
TR_EXPORT TR_NAME *tid_resp_get_orig_coi(TID_RESP *resp);
void tid_resp_set_orig_coi(TID_RESP *resp, TR_NAME *orig_coi);
TR_EXPORT TID_SRVR_BLK *tid_resp_get_server(TID_RESP *resp, size_t index);
TR_EXPORT size_t tid_resp_get_num_servers(const TID_RESP *resp);
TR_EXPORT const TID_PATH *tid_resp_get_error_path(const TID_RESP *);

/** Get either the error_path or the path of the first server block for
 * a successful response*/
TR_EXPORT const TID_PATH *tid_resp_get_a_path(const TID_RESP *);
/* Server blocks*/
TR_EXPORT void tid_srvr_get_address(const TID_SRVR_BLK *,
				    const struct sockaddr **out_addr, size_t *out_sa_len);
TR_EXPORT DH *tid_srvr_get_dh(TID_SRVR_BLK *);
TR_EXPORT const TR_NAME *tid_srvr_get_key_name(const TID_SRVR_BLK *);
TR_EXPORT const TID_PATH *tid_srvr_get_path(const TID_SRVR_BLK *);
/* Key expiration time is expressed as time since 1970-01-01 00:00:00 UTC */
TR_EXPORT int tid_srvr_get_key_expiration(const TID_SRVR_BLK *, struct timeval *tv_out);

#define tid_resp_servers_foreach(RESP, SERVER, INDEX) \
  for (INDEX=0,SERVER=NULL;						\
       ((INDEX < tid_resp_get_num_servers(RESP))&&(SERVER = tid_resp_get_server(resp, INDEX))); \
       INDEX++)


/* TID Client functions, in tid/tidc.c */
TR_EXPORT TIDC_INSTANCE *tidc_create (void);
TR_EXPORT int tidc_open_connection (TIDC_INSTANCE *tidc, const char *server, unsigned int port, gss_ctx_id_t *gssctx);
TR_EXPORT int tidc_send_request (TIDC_INSTANCE *tidc, int conn, gss_ctx_id_t gssctx, const char *rp_realm, const char *realm, const char *coi, TIDC_RESP_FUNC *resp_handler, void *cookie);
TR_EXPORT int tidc_fwd_request (TIDC_INSTANCE *tidc, TID_REQ *req, TIDC_RESP_FUNC *resp_handler, void *cookie);
TR_EXPORT DH *tidc_get_dh(TIDC_INSTANCE *);
TR_EXPORT DH *tidc_set_dh(TIDC_INSTANCE *, DH *);
TR_EXPORT void tidc_destroy(TIDC_INSTANCE *tidc);

/* TID Server functions, in tid/tids.c */
TIDS_INSTANCE *tids_new(TALLOC_CTX *mem_ctx);
TR_EXPORT TIDS_INSTANCE *tids_create (void);
TR_EXPORT int tids_start (TIDS_INSTANCE *tids, TIDS_REQ_FUNC *req_handler,
                          tids_auth_func *auth_handler, const char *hostname,
                          unsigned int port, void *cookie);
TR_EXPORT int tids_get_listener (TIDS_INSTANCE *tids, TIDS_REQ_FUNC *req_handler,
                                 tids_auth_func *auth_handler, const char *hostname,
                                 unsigned int port, void *cookie, int *fd_out, size_t max_fd);
TR_EXPORT int tids_accept(TIDS_INSTANCE *tids, int listen);
TR_EXPORT int tids_send_response (TIDS_INSTANCE *tids, TID_REQ *req, TID_RESP *resp);
TR_EXPORT int tids_send_err_response (TIDS_INSTANCE *tids, TID_REQ *req, const char *err_msg);
TR_EXPORT void tids_destroy (TIDS_INSTANCE *tids);

#endif
