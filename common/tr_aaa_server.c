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


#include <talloc.h>

#include <tr_name_internal.h>
#include <tr_aaa_server.h>
#include <trust_router/tid.h>
#include <tr_util.h>
#include <tr_inet_util.h>

static int tr_aaa_server_destructor(void *obj)
{
  TR_AAA_SERVER *aaa=talloc_get_type_abort(obj, TR_AAA_SERVER);
  if (aaa->hostname!=NULL)
    tr_free_name(aaa->hostname);
  return 0;
}

TR_AAA_SERVER *tr_aaa_server_new(TALLOC_CTX *mem_ctx)
{
  TR_AAA_SERVER *aaa=talloc(mem_ctx, TR_AAA_SERVER);
  if (aaa!=NULL) {
    aaa->next=NULL;
    aaa->hostname = NULL;
    tr_aaa_server_set_port(aaa, 0); /* go through setter to guarantee consistent default */
    talloc_set_destructor((void *)aaa, tr_aaa_server_destructor);
  }
  return aaa;
}

void tr_aaa_server_free(TR_AAA_SERVER *aaa)
{
  talloc_free(aaa);
}

TR_NAME *tr_aaa_server_get_hostname(TR_AAA_SERVER *aaa)
{
  return aaa->hostname;
}

/**
 * Set the hostname for a AAA server
 *
 * Takes ownership of the TR_NAME. Does nothing if aaa is null.
 *
 * @param aaa
 * @param hostname
 */
void tr_aaa_server_set_hostname(TR_AAA_SERVER *aaa, TR_NAME *hostname)
{
  if (aaa == NULL)
    return;

  if (aaa->hostname != NULL) {
    tr_free_name(aaa->hostname);
  }

  aaa->hostname = hostname;
}

int tr_aaa_server_get_port(TR_AAA_SERVER *aaa)
{
  return aaa->port;
}

/**
 * Set the port for a AAA server
 *
 * If port is 0, uses the standard TID port (12309). Other invalid values are stored
 * as-is.
 *
 * Does nothing if aaa is null.
 *
 * @param aaa
 * @param port
 */
void tr_aaa_server_set_port(TR_AAA_SERVER *aaa, int port)
{
  if (aaa == NULL)
    return;

  if (port == 0)
    port = TID_PORT;

  aaa->port = port;
}

/**
 * Allocate a AAA server record and fill it in by parsing a hostname:port string
 *
 * If hostname or port are invalid, hostname will be empty and port will be -1.
 *
 * @return newly allocated TR_AAA_SERVER in the mem_ctx context, or NULL on error
 */
TR_AAA_SERVER *tr_aaa_server_from_string(TALLOC_CTX *mem_ctx, const char *s)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  TR_AAA_SERVER *aaa = tr_aaa_server_new(tmp_ctx);
  char *hostname;
  int port;

  if (aaa == NULL)
    goto failed;

  hostname = tr_parse_host(tmp_ctx, s, &port);
  if (NULL == hostname) {
    hostname = "";
    port = -1;
  }

  tr_aaa_server_set_hostname(aaa, tr_new_name(hostname));
  if (tr_aaa_server_get_hostname(aaa) == NULL)
    goto failed;

  tr_aaa_server_set_port(aaa, port); /* port = 0 uses default TID port */
  talloc_steal(mem_ctx, aaa); /*put this in the caller's context */
  goto succeeded;

failed:
  aaa = NULL; /* talloc will free the memory if it was allocated */

succeeded:
  talloc_free(tmp_ctx);
  return aaa;
}

TR_AAA_SERVER_ITER *tr_aaa_server_iter_new(TALLOC_CTX *mem_ctx)
{
  return talloc(mem_ctx, TR_AAA_SERVER_ITER);
}

void tr_aaa_server_iter_free(TR_AAA_SERVER_ITER *iter)
{
  talloc_free(iter);
}

TR_AAA_SERVER *tr_aaa_server_iter_first(TR_AAA_SERVER_ITER *iter, TR_AAA_SERVER *aaa)
{
  iter->this=aaa;
  return iter->this;
}

TR_AAA_SERVER *tr_aaa_server_iter_next(TR_AAA_SERVER_ITER *iter)
{
  if (iter->this!=NULL) {
    iter->this=iter->this->next;
  }
  return iter->this;
}
