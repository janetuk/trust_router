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

#include <talloc.h>
#include <pthread.h>

#include <tr_mq.h>
#include <tr_debug.h>

/* Messages */
static int tr_mq_msg_destructor(void *object)
{
  TR_MQ_MSG *msg=talloc_get_type_abort(object, TR_MQ_MSG);
  if ( (msg->p!=NULL) && (msg->p_free!=NULL))
    msg->p_free(msg->p);
  return 0;
}

TR_MQ_MSG *tr_mq_msg_new(TALLOC_CTX *mem_ctx, const char *message, TR_MQ_PRIORITY prio)
{
  TR_MQ_MSG *msg=talloc(mem_ctx, TR_MQ_MSG);
  if (msg!=NULL) {
    msg->next=NULL;
    msg->prio=prio;
    msg->message=talloc_strdup(msg, message);
    if (msg->message==NULL) {
      talloc_free(msg);
      return NULL;
    }
    msg->p=NULL;
    talloc_set_destructor((void *)msg, tr_mq_msg_destructor);
  }
  return msg;
}

void tr_mq_msg_free(TR_MQ_MSG *msg)
{
  if (msg!=NULL)
    talloc_free(msg);
}

TR_MQ_PRIORITY tr_mq_msg_get_prio(TR_MQ_MSG *msg)
{
  return msg->prio;
}

const char *tr_mq_msg_get_message(TR_MQ_MSG *msg)
{
  return msg->message;
}

void *tr_mq_msg_get_payload(TR_MQ_MSG *msg)
{
  return msg->p;
}

/* call with a pointer to the payload and a function to free it later */
void tr_mq_msg_set_payload(TR_MQ_MSG *msg, void *p, void (*p_free)(void *))
{
  msg->p=p;
  msg->p_free=p_free;
}


static TR_MQ_MSG *tr_mq_msg_get_next(TR_MQ_MSG *msg)
{
  return msg->next;
}

static void tr_mq_msg_set_next(TR_MQ_MSG *msg, TR_MQ_MSG *next)
{
  msg->next=next;
}

/* Message Queues */
TR_MQ *tr_mq_new(TALLOC_CTX *mem_ctx)
{
  TR_MQ *mq=talloc(mem_ctx, TR_MQ);
  if (mq!=NULL) {
    pthread_mutex_init(&(mq->mutex), 0);
    mq->head=NULL;
    mq->tail=NULL;
    mq->last_hi_prio=NULL;
  }
  return mq;
}

void tr_mq_free(TR_MQ *mq)
{
  if (mq!=NULL) {
    tr_mq_lock(mq); /* don't pull the rug out from under someone */
    talloc_free(mq);
  }
}

int tr_mq_lock(TR_MQ *mq)
{
  return pthread_mutex_lock(&(mq->mutex));
}

int tr_mq_unlock(TR_MQ *mq)
{
  return pthread_mutex_unlock(&(mq->mutex));
}

static TR_MQ_MSG *tr_mq_get_head(TR_MQ *mq)
{
  return mq->head;
}

static void tr_mq_set_head(TR_MQ *mq, TR_MQ_MSG *msg)
{
  mq->head=msg;
}

static TR_MQ_MSG *tr_mq_get_tail(TR_MQ *mq)
{
  return mq->tail;
}

static void tr_mq_set_tail(TR_MQ *mq, TR_MQ_MSG *msg)
{
  mq->tail=msg;
}

void tr_mq_set_notify_cb(TR_MQ *mq, TR_MQ_NOTIFY_FN cb, void *arg)
{
  mq->notify_cb=cb;
  mq->notify_cb_arg=arg;
}

void tr_mq_clear(TR_MQ *mq)
{
  TR_MQ_MSG *m=NULL;
  TR_MQ_MSG *n=NULL;

  tr_mq_lock(mq);
  m=tr_mq_get_head(mq);
  while (m!=NULL) {
    n=tr_mq_msg_get_next(m);
    tr_mq_msg_free(m);
    m=n;
  }
  tr_mq_set_head(mq, NULL);
  tr_mq_set_tail(mq, NULL);
  tr_mq_unlock(mq);
}

static int tr_mq_empty(TR_MQ *mq)
{
  return tr_mq_get_head(mq)==NULL;
}

/* puts msg in mq's talloc context */
static void tr_mq_append(TR_MQ *mq, TR_MQ_MSG *msg)
{
  if (tr_mq_get_head(mq)==NULL) {
    tr_mq_set_head(mq, msg);
    tr_mq_set_tail(mq, msg);
  } else {
    tr_mq_msg_set_next(tr_mq_get_tail(mq), msg); /* add to list */
    tr_mq_set_tail(mq, msg); /* update tail of list */
  }
  talloc_steal(mq, msg);
}

static void tr_mq_append_high_prio(TR_MQ *mq, TR_MQ_MSG *new)
{
  if (tr_mq_get_head(mq)==NULL) {
    tr_mq_set_head(mq, new);
    tr_mq_set_tail(mq, new);
  } else if (mq->last_hi_prio==NULL) {
    tr_mq_msg_set_next(new, tr_mq_get_head(mq)); /* add to front of list */
    tr_mq_set_head(mq, new); /* update head of list */
  } else {
    tr_mq_msg_set_next(new, tr_mq_msg_get_next(mq->last_hi_prio));
    tr_mq_msg_set_next(mq->last_hi_prio, new); /* add to end of hi prio msgs */
  }
  mq->last_hi_prio=new; /* in any case, this is now the last high priority msg */
  talloc_steal(mq,new);
}

#define DEBUG_TR_MQ 0
#if DEBUG_TR_MQ
static void tr_mq_print(TR_MQ *mq)
{
  TR_MQ_MSG *m=mq->head;
  int ii=0;

  tr_debug("tr_mq_print: mq contents:");
  while(m!=NULL) {
    ii++;
    tr_debug("tr_mq_print: Entry %02d: %-15s (prio %d)",
             ii, tr_mq_msg_get_message(m), tr_mq_msg_get_prio(m));
    m=tr_mq_msg_get_next(m);
  }
}
#endif
void tr_mq_add(TR_MQ *mq, TR_MQ_MSG *msg)
{
  int was_empty=0;
  TR_MQ_NOTIFY_FN notify_cb=NULL;
  void *notify_cb_arg=NULL;

  tr_mq_lock(mq);
  
  was_empty=tr_mq_empty(mq);
  switch (tr_mq_msg_get_prio(msg)) {
  case TR_MQ_PRIO_HIGH:
    tr_mq_append_high_prio(mq, msg);
    break;
  default:
    tr_mq_append(mq, msg);
    break;
  }
  /* before releasing the mutex, get notify_cb data out of mq */
  notify_cb=mq->notify_cb;
  notify_cb_arg=mq->notify_cb_arg;

#if DEBUG_TR_MQ
  tr_mq_print(mq);
#endif 

  tr_mq_unlock(mq);

  /* see if we need to tell someone we became non-empty */
  if (was_empty && (notify_cb!=NULL))
    notify_cb(mq, notify_cb_arg);
}

/* caller must free msg via tr_mq_msg_free */
TR_MQ_MSG *tr_mq_pop(TR_MQ *mq)
{
  TR_MQ_MSG *popped=NULL;

  tr_mq_lock(mq);
  if (tr_mq_get_head(mq)!=NULL) {
    popped=tr_mq_get_head(mq);
    tr_mq_set_head(mq, tr_mq_msg_get_next(popped)); /* popped is the old head */

    if (popped==mq->last_hi_prio)
      mq->last_hi_prio=NULL;

    if (tr_mq_get_head(mq)==NULL)
      tr_mq_set_tail(mq, NULL); /* just popped the last element */
  }
  tr_mq_unlock(mq);
  if (popped!=NULL)
    tr_mq_msg_set_next(popped, NULL); /* disconnect from list */
  return popped;
}

