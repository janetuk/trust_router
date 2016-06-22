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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <tr_mq.h>

static void notify_cb(TR_MQ *mq, void *arg)
{
  char *s=(char *)arg;

  printf("MQ %s no longer empty.\n", s);
}

int main(void)
{
  TR_MQ *mq=NULL;
  TR_MQ_MSG *msg=NULL;
  TR_MQ_MSG *msg1=NULL;
  TR_MQ_MSG *msg2=NULL;
  TR_MQ_MSG *msg3=NULL;
  TR_MQ_MSG *msg4=NULL;
  char *mq_name="1";

  mq=tr_mq_new(NULL);
  mq->notify_cb=notify_cb;
  mq->notify_cb_arg=mq_name;

  msg1=tr_mq_msg_new(NULL);
  asprintf((char **)&(msg1->p), "First message.\n");
  msg1->p_free=free;
  tr_mq_append(mq, msg1);
  assert(mq->head==msg1);
  assert(mq->tail==msg1);
  assert(msg1->next==NULL);

  msg2=tr_mq_msg_new(NULL);
  asprintf((char **)&(msg2->p), "Second message.\n");
  msg2->p_free=free;
  tr_mq_append(mq, msg2);
  assert(mq->head==msg1);
  assert(msg1->next==msg2);
  assert(mq->tail==msg2);
  assert(msg2->next==NULL);

  msg=tr_mq_pop(mq);
  assert(msg==msg1);
  assert(mq->head==msg2);
  assert(mq->tail==msg2);
  assert(msg2->next==NULL);
  if ((msg!=NULL) && (msg->p!=NULL)) {
    printf((char *)msg->p);
    tr_mq_msg_free(msg);
  } else
    printf("no message to pop\n");
  
  msg3=tr_mq_msg_new(NULL);
  asprintf((char **)&(msg3->p), "Third message.\n");
  msg3->p_free=free;
  tr_mq_append(mq, msg3);
  assert(mq->head==msg2);
  assert(mq->tail==msg3);
  assert(msg2->next==msg3);
  assert(msg3->next==NULL);

  msg=tr_mq_pop(mq);
  assert(msg==msg2);
  assert(mq->head==msg3);
  assert(mq->tail==msg3);
  assert(msg3->next==NULL);
  if ((msg!=NULL) && (msg->p!=NULL)) {
    printf((char *)msg->p);
    tr_mq_msg_free(msg);
  } else
    printf("no message to pop\n");
  
  msg=tr_mq_pop(mq);
  assert(msg==msg3);
  assert(mq->head==NULL);
  assert(mq->tail==NULL);
  if ((msg!=NULL) && (msg->p!=NULL)) {
    printf((char *)msg->p);
    tr_mq_msg_free(msg);
  } else
    printf("no message to pop\n");
  
  msg=tr_mq_pop(mq);
  assert(msg==NULL);
  assert(mq->head==NULL);
  assert(mq->tail==NULL);
  if ((msg!=NULL) && (msg->p!=NULL)) {
    printf((char *)msg->p);
    tr_mq_msg_free(msg);
  } else
    printf("no message to pop\n");

  msg4=tr_mq_msg_new(NULL);
  asprintf((char **)&(msg4->p), "Fourth message.\n");
  msg4->p_free=free;
  tr_mq_append(mq, msg4);
  assert(mq->head==msg4);
  assert(mq->tail==msg4);
  assert(msg4->next==NULL);

  msg=tr_mq_pop(mq);
  assert(msg==msg4);
  assert(mq->head==NULL);
  assert(mq->tail==NULL);
  if ((msg!=NULL) && (msg->p!=NULL)) {
    printf((char *)msg->p);
    tr_mq_msg_free(msg);
  } else
    printf("no message to pop\n");
  
  msg=tr_mq_pop(mq);
  assert(msg==NULL);
  assert(mq->head==NULL);
  assert(mq->tail==NULL);
  if ((msg!=NULL) && (msg->p!=NULL)) {
    printf((char *)msg->p);
    tr_mq_msg_free(msg);
  } else
    printf("no message to pop\n");

  tr_mq_free(mq);

  return 0;
}
