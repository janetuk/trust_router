/*
 * Copyright (c) 2012-2018, JANET(UK)
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

#ifndef TRUST_ROUTER_TR_AAA_SERVER_H
#define TRUST_ROUTER_TR_AAA_SERVER_H

#include <talloc.h>

#include <tr_name_internal.h>

typedef struct tr_aaa_server {
  struct tr_aaa_server *next;
  TR_NAME *hostname;
  int port;
} TR_AAA_SERVER;

typedef struct tr_aaa_server_iter {
  TR_AAA_SERVER *this;
} TR_AAA_SERVER_ITER;

TR_AAA_SERVER *tr_aaa_server_new(TALLOC_CTX *mem_ctx, TR_NAME *hostname);
void tr_aaa_server_free(TR_AAA_SERVER *aaa);

TR_NAME *tr_aaa_server_get_hostname(TR_AAA_SERVER *aaa);
void tr_aaa_server_set_hostname(TR_AAA_SERVER *aaa, TR_NAME *hostname);
int tr_aaa_server_get_port(TR_AAA_SERVER *aaa);
void tr_aaa_server_set_port(TR_AAA_SERVER *aaa, int port);

TR_AAA_SERVER_ITER *tr_aaa_server_iter_new(TALLOC_CTX *mem_ctx);
void tr_aaa_server_iter_free(TR_AAA_SERVER_ITER *iter);
TR_AAA_SERVER *tr_aaa_server_iter_first(TR_AAA_SERVER_ITER *iter, TR_AAA_SERVER *aaa);
TR_AAA_SERVER *tr_aaa_server_iter_next(TR_AAA_SERVER_ITER *iter);

#endif //TRUST_ROUTER_TR_AAA_SERVER_H
