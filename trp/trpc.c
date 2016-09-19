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

#include <fcntl.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>

#include <gsscon.h>
#include <tr_rp.h>
#include <tr_debug.h>
#include <trp_internal.h>

static int trpc_destructor(void *object)
{
  TRPC_INSTANCE *trpc=talloc_get_type_abort(object, TRPC_INSTANCE);
  if (trpc->gssname!=NULL)
    tr_free_name(trpc->gssname);
  return 0;
}

/* also allocates the incoming mq */
TRPC_INSTANCE *trpc_new (TALLOC_CTX *mem_ctx)
{
  TRPC_INSTANCE *trpc=talloc(mem_ctx, TRPC_INSTANCE);
  if (trpc!=NULL) {
    trpc->next=NULL;
    trpc->server=NULL;
    trpc->port=0;
    trpc->conn=NULL;
    trpc->mq=tr_mq_new(trpc);
    if (trpc->mq==NULL) {
      talloc_free(trpc);
      trpc=NULL;
    } else
      talloc_set_destructor((void *)trpc, trpc_destructor);
    
  }
  return trpc;
}

void trpc_free (TRPC_INSTANCE *trpc)
{
  if (trpc)
    talloc_free(trpc);
}

TRPC_INSTANCE *trpc_get_next(TRPC_INSTANCE *trpc)
{
  return trpc->next;
}

void trpc_set_next(TRPC_INSTANCE *trpc, TRPC_INSTANCE *next)
{
  trpc->next=next;
}

/* Ok to call more than once; guarantees trpc no longer in the list. Does not free removed element.
 * Returns handle to new list, you must replace your old handle on the list with this.  */
TRPC_INSTANCE *trpc_remove(TRPC_INSTANCE *trpc, TRPC_INSTANCE *remove)
{
  TRPC_INSTANCE *cur=trpc;
  TRPC_INSTANCE *last=NULL;

  if (cur==NULL)
    return NULL;

  /* first element is a special case */
  if (cur==remove) {
    trpc=trpc_get_next(cur); /* advance list head */
  } else {
    /* it was not the first element */
    last=cur;
    cur=trpc_get_next(cur);
    while (cur!=NULL) {
      if (cur==remove) {
        trpc_set_next(last, trpc_get_next(cur));
        break;
      }
      last=cur;
      cur=trpc_get_next(cur);
    }
  }
  return trpc;
}

static TRPC_INSTANCE *trpc_get_tail(TRPC_INSTANCE *trpc)
{
  while((trpc!=NULL)&&(trpc_get_next(trpc)!=NULL))
    trpc=trpc_get_next(trpc);
  return trpc;
}

void trpc_append(TRPC_INSTANCE *trpc, TRPC_INSTANCE *new)
{
  trpc_set_next(trpc_get_tail(trpc), new);
}

char *trpc_get_server(TRPC_INSTANCE *trpc)
{
  return trpc->server;
}

void trpc_set_server(TRPC_INSTANCE *trpc, char *server)
{
  trpc->server=server;
}

TR_NAME *trpc_get_gssname(TRPC_INSTANCE *trpc)
{
  return trpc->gssname;
}

/* takes responsibility for freeing gssname */
void trpc_set_gssname(TRPC_INSTANCE *trpc, TR_NAME *gssname)
{
  trpc->gssname=gssname;
}

unsigned int trpc_get_port(TRPC_INSTANCE *trpc)
{
  return trpc->port;
}

void trpc_set_port(TRPC_INSTANCE *trpc, unsigned int port)
{
  trpc->port=port;
}

TRP_CONNECTION *trpc_get_conn(TRPC_INSTANCE *trpc)
{
  return trpc->conn;
}

void trpc_set_conn(TRPC_INSTANCE *trpc, TRP_CONNECTION *conn)
{
  trpc->conn=conn;
}

TRP_CONNECTION_STATUS trpc_get_status(TRPC_INSTANCE *trpc)
{
  return trp_connection_get_status(trpc_get_conn(trpc));
}

TR_MQ *trpc_get_mq(TRPC_INSTANCE *trpc)
{
  return trpc->mq;
}

void trpc_set_mq(TRPC_INSTANCE *trpc, TR_MQ *mq)
{
  trpc->mq=mq;
}

/* submit msg to trpc for transmission */
void trpc_mq_add(TRPC_INSTANCE *trpc, TR_MQ_MSG *msg)
{
  tr_mq_add(trpc->mq, msg);
}

TR_MQ_MSG *trpc_mq_pop(TRPC_INSTANCE *trpc)
{
  return tr_mq_pop(trpc->mq);
}

void trpc_mq_clear(TRPC_INSTANCE *trpc)
{
  tr_mq_clear(trpc->mq);
}

TRP_RC trpc_connect(TRPC_INSTANCE *trpc)
{
  return trp_connection_initiate(trpc_get_conn(trpc), trpc_get_server(trpc), trpc_get_port(trpc));
}

/* simple function, based on tidc_send_req */
TRP_RC trpc_send_msg (TRPC_INSTANCE *trpc, 
                      const char *msg_content)
{
  int err=0;
  TRP_RC rc=TRP_SUCCESS;

  /* Send the request over the connection */
  if (err = gsscon_write_encrypted_token(trp_connection_get_fd(trpc_get_conn(trpc)),
                                         *trp_connection_get_gssctx(trpc_get_conn(trpc)),
                                         msg_content, 
                                         strlen(msg_content))) {
    tr_err( "trpc_send_msg: Error sending message over connection.\n");
    rc=TRP_ERROR;
  }
  return rc;
}
