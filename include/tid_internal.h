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

#ifndef TID_INTERNAL_H
#define TID_INTERNAL_H
#include <trust_router/tid.h>

#include <jansson.h>
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
  TR_CONSTRAINT_SET *cons;
  TR_NAME *orig_coi;
  TID_SRVR_BLK *servers;       	/* Linked list of servers */
  /* TBD -- Trust Path Used */
} TID_RESP;
struct tid_req {
  struct tid_req *next_req;
  int resp_sent;
  int conn;
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
  json_t *json_references; /** References to objects dereferenced on request destruction*/
};
struct tidc_instance {
  TID_REQ *req_list;
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
  tids_auth_func *auth_handler;
  void *cookie;
};


/** Decrement a reference to #json when this tid_req is cleaned up. A
    new reference is not created; in effect the caller is handing a
    reference they already hold to the TID_REQ.*/
void tid_req_cleanup_json(TID_REQ *, json_t *json);

#endif
