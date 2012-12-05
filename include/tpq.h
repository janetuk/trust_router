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

#ifndef TPQ_H
#define TPQ_H

#define TPQ_PORT	12309

#include <gsscon.h>
typedef struct tpq_name {
  char *buf;
  int len;
} TPQ_NAME;

typedef struct tpq_req {
  struct tpq_req *next_req;
  int conn;
  TPQ_NAME *realm;
  TPQ_NAME *coi;
  void *resp_func;
  void *cookie;
} TPQ_REQ;

typedef struct tpq_resp {
  TPQ_NAME *realm;
  TPQ_NAME *coi;
  /* Address of AAA Server */
  /* Credentials */
  /* Trust Path Used */
} TPQ_RESP;

typedef struct tpqc_instance {
  TPQ_REQ *req_list;
} TPQC_INSTANCE;

typedef struct tpqs_instance {
  int req_count;
  void *req_handler;
  void *cookie;
} TPQS_INSTANCE;

typedef void (TPQC_RESP_FUNC)(TPQC_INSTANCE *, TPQ_RESP *, void *);
typedef int (TPQS_REQ_FUNC)(TPQS_INSTANCE *, TPQ_REQ *, TPQ_RESP *, void *);

TPQ_NAME *tpq_new_name (char *name);
TPQ_NAME *tpq_dup_name (TPQ_NAME *from);

char *tpq_req_encode(TPQ_REQ *req);
TPQ_REQ *tpq_req_decode(char *jreq);
char *tpq_resp_encode(TPQ_REQ *resp);
TPQ_RESP *tpq_resp_decode(char *jresp);

TPQC_INSTANCE *tpqc_create (void);
int tpqc_open_connection (TPQC_INSTANCE *tpqc, char *server, gss_ctx_id_t *gssctx);
int tpqc_send_request (TPQC_INSTANCE *tpqc, int conn, gss_ctx_id_t gssctx, char *realm, char *coi, TPQC_RESP_FUNC *resp_handler, void *cookie);
void tpqc_destroy (TPQC_INSTANCE *tpqc);

TPQS_INSTANCE *tpqs_create ();
int tpqs_start (TPQS_INSTANCE *tpqs, TPQS_REQ_FUNC *req_handler, void *cookie);
void tpqs_destroy (TPQS_INSTANCE *tpqs);

#endif
