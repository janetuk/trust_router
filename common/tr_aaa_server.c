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

static int tr_aaa_server_destructor(void *obj)
{
  TR_AAA_SERVER *aaa=talloc_get_type_abort(obj, TR_AAA_SERVER);
  if (aaa->hostname!=NULL)
    tr_free_name(aaa->hostname);
  return 0;
}

TR_AAA_SERVER *tr_aaa_server_new(TALLOC_CTX *mem_ctx, TR_NAME *hostname)
{
  TR_AAA_SERVER *aaa=talloc(mem_ctx, TR_AAA_SERVER);
  if (aaa!=NULL) {
    aaa->next=NULL;
    aaa->hostname=hostname;
    talloc_set_destructor((void *)aaa, tr_aaa_server_destructor);
  }
  return aaa;
}

void tr_aaa_server_free(TR_AAA_SERVER *aaa)
{
  talloc_free(aaa);
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
 * If port is outside the range 1-65535, uses the standard TID port (12309).
 * Does nothing if aaa is null.
 *
 * @param aaa
 * @param port
 */
void tr_aaa_server_set_port(TR_AAA_SERVER *aaa, int port)
{
  if (aaa == NULL)
    return;

  if ((port <= 0) || (port > 65535))
    port = TID_PORT;

  aaa->port = port;
}


