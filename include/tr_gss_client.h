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

#ifndef TRUST_ROUTER_TR_GSS_CLIENT_H
#define TRUST_ROUTER_TR_GSS_CLIENT_H

#include <gssapi.h>
#include <tr_msg.h>

typedef struct tr_gssc_instance TR_GSSC_INSTANCE;

/* Client instance */
struct tr_gssc_instance {
  const char *service_name;
  gss_ctx_id_t *gss_ctx;
  int conn;
};

/* tr_gss_client.c */
TR_GSSC_INSTANCE *tr_gssc_instance_new(TALLOC_CTX *mem_ctx);
void tr_gssc_instance_free(TR_GSSC_INSTANCE *tr_gssc);
int tr_gssc_open_connection(TR_GSSC_INSTANCE *gssc, const char *server, int port);
TR_MSG *tr_gssc_exchange_msgs(TALLOC_CTX *mem_ctx, TR_GSSC_INSTANCE *gssc, TR_MSG *req_msg);

#endif //TRUST_ROUTER_TR_GSS_CLIENT_H
