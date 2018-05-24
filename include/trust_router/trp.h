/*
 * Copyright (c) 2016, JANET(UK)
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

#ifndef TRP_H
#define TRP_H

#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trust_router/tr_versioning.h>

#define TRP_PORT 12308
#define TRP_METRIC_INFINITY 0xFFFF
#define TRP_METRIC_INVALID 0xFFFFFFFF
#define trp_metric_is_finite(x) (((x)<TRP_METRIC_INFINITY) && ((x)!=TRP_METRIC_INVALID))
#define trp_metric_is_infinite(x) ((x)==TRP_METRIC_INFINITY)
#define trp_metric_is_valid(x) (((x)<=TRP_METRIC_INFINITY) && ((x)!=TRP_METRIC_INVALID))
#define trp_metric_is_invalid(x) (((x)>TRP_METRIC_INFINITY) || ((x)==TRP_METRIC_INVALID))
#define TRP_INTERVAL_INVALID 0

#define TRP_LINKCOST_DEFAULT 1

typedef enum trp_rc {
  TRP_SUCCESS=0,
  TRP_ERROR, /* generic error */
  TRP_NOPARSE, /* parse error */
  TRP_NOMEM, /* allocation error */
  TRP_BADTYPE, /* typing error */
  TRP_UNSUPPORTED, /* unsupported feature */
  TRP_BADARG, /* bad argument */
  TRP_CLOCKERR, /* error reading time */
  TRP_MISSING, /* value not present */
} TRP_RC;

typedef enum trp_inforec_type {
  TRP_INFOREC_TYPE_UNKNOWN=0, /* conveniently, JSON parser returns 0 if a non-integer number is specified */
  TRP_INFOREC_TYPE_ROUTE,
  TRP_INFOREC_TYPE_COMMUNITY
} TRP_INFOREC_TYPE;

typedef struct trp_inforec TRP_INFOREC;

typedef struct trp_update TRP_UPD;
typedef struct trp_req TRP_REQ;

/* Functions for TRP_UPD structures */
TR_EXPORT TRP_UPD *trp_upd_new(TALLOC_CTX *mem_ctx);
void trp_upd_free(TRP_UPD *update);
TR_EXPORT TRP_INFOREC *trp_upd_get_inforec(TRP_UPD *upd);
void trp_upd_set_inforec(TRP_UPD *upd, TRP_INFOREC *rec);
void trp_upd_add_inforec(TRP_UPD *upd, TRP_INFOREC *rec);
void trp_upd_remove_inforec(TRP_UPD *upd, TRP_INFOREC *rec);
size_t trp_upd_num_inforecs(TRP_UPD *upd);
TR_EXPORT TR_NAME *trp_upd_get_realm(TRP_UPD *upd);
TR_NAME *trp_upd_dup_realm(TRP_UPD *upd);
void trp_upd_set_realm(TRP_UPD *upd, TR_NAME *realm);
TR_EXPORT TR_NAME *trp_upd_get_comm(TRP_UPD *upd);
TR_NAME *trp_upd_dup_comm(TRP_UPD *upd);
void trp_upd_set_comm(TRP_UPD *upd, TR_NAME *comm);
TR_EXPORT TR_NAME *trp_upd_get_peer(TRP_UPD *upd);
TR_NAME *trp_upd_dup_peer(TRP_UPD *upd);
void trp_upd_set_peer(TRP_UPD *upd, TR_NAME *peer);
void trp_upd_set_next_hop(TRP_UPD *upd, const char *hostname, unsigned int port);
void trp_upd_add_to_provenance(TRP_UPD *upd, TR_NAME *name);

/* Functions for TRP_REQ structures */
TR_EXPORT TRP_REQ *trp_req_new(TALLOC_CTX *mem_ctx);
TR_EXPORT void trp_req_free(TRP_REQ *req);
TR_EXPORT TR_NAME *trp_req_get_comm(TRP_REQ *req);
void trp_req_set_comm(TRP_REQ *req, TR_NAME *comm);
TR_EXPORT TR_NAME *trp_req_get_realm(TRP_REQ *req);
void trp_req_set_realm(TRP_REQ *req, TR_NAME *realm);
TR_EXPORT TR_NAME *trp_req_get_peer(TRP_REQ *req);
void trp_req_set_peer(TRP_REQ *req, TR_NAME *peer);
int trp_req_is_wildcard(TRP_REQ *req);
TRP_RC trp_req_make_wildcard(TRP_REQ *req);

#endif /* TRP_H */
