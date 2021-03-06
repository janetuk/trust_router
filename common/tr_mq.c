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
#include <time.h>
#include <errno.h>

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

TR_MQ_MSG *tr_mq_msg_new(TALLOC_CTX *mem_ctx, const char *message)
{
  TR_MQ_MSG *msg=talloc(mem_ctx, TR_MQ_MSG);
  if (msg!=NULL) {
    msg->next=NULL;
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
  pthread_condattr_t cattr;

  if (mq!=NULL) {
    pthread_mutex_init(&(mq->mutex), 0);
    pthread_condattr_init(&cattr);

    pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC); /* use the monotonic clock for timeouts */
    pthread_cond_init(&(mq->have_msg_cond), &cattr);
    pthread_condattr_destroy(&cattr);

    mq->head=NULL;
    mq->tail=NULL;

    mq->notify_cb=NULL;
    mq->notify_cb_arg=NULL;
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

#define DEBUG_TR_MQ 0
#if DEBUG_TR_MQ
static void tr_mq_print(TR_MQ *mq)
{
  TR_MQ_MSG *m=mq->head;
  int ii=0;

  tr_debug("tr_mq_print: mq contents:");
  while(m!=NULL) {
    ii++;
    tr_debug("tr_mq_print: Entry %02d: %-15s",
             ii, tr_mq_msg_get_message(m));
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
  tr_mq_append(mq, msg);

  /* before releasing the mutex, get notify_cb data out of mq */
  notify_cb=mq->notify_cb;
  notify_cb_arg=mq->notify_cb_arg;

#if DEBUG_TR_MQ
  tr_mq_print(mq);
#endif 

  /* Before releasing the lock, signal any waiting threads that there's now
   * something in the queue. Used for blocking tr_mq_pop() call. */

  if (was_empty)
    pthread_cond_broadcast(&(mq->have_msg_cond));

  tr_mq_unlock(mq);

  /* see if we need to tell someone we became non-empty */
  if (was_empty && (notify_cb!=NULL))
    notify_cb(mq, notify_cb_arg);
}

/* Compute an absolute time from a desired timeout interval for use with tr_mq_pop().
 * Fills in *ts and returns 0 on success. */
int tr_mq_pop_timeout(time_t seconds, struct timespec *ts)
{
  if (0!=clock_gettime(CLOCK_MONOTONIC, ts))
    return -1;

  ts->tv_sec+=seconds;
  return 0;
}

/* Retrieves a message from the queue, waiting until absolute
 * time ts_abort before giving up (using CLOCK_MONOTONIC). If ts_abort
 * has passed, returns an existing message but will not wait if one is
 * not already available. If ts_abort is null, no blocking.  Not
 * guaranteed to wait if an error occurs - immediately returns without
 * a message. Use tr_mq_pop_timeout() to get an absolute time that
 * is guaranteed compatible with this function.
 *
 * Caller should free msg via tr_mq_msg_free when done with it. It stays
 * in the TR_MQ's context, though, so use talloc_steal() if you want to do
 * something clever with it. */
TR_MQ_MSG *tr_mq_pop(TR_MQ *mq, struct timespec *ts_abort)
{
  TR_MQ_MSG *popped=NULL;
  int wait_err=0;
  
  tr_mq_lock(mq);
  if ((tr_mq_get_head(mq)==NULL) && (ts_abort!=NULL)) {
    /* No msgs yet, and blocking was requested */
    while ((wait_err==0) && (NULL==tr_mq_get_head(mq)))
      wait_err=pthread_cond_timedwait(&(mq->have_msg_cond),
                                     &(mq->mutex),
                                     ts_abort);
    
    if ((wait_err!=0) && (wait_err!=ETIMEDOUT)) {
      tr_notice("tr_mq_pop: error waiting for message.");
      return NULL;
    }
    /* if it timed out, ok to go ahead and check once more for a message, so no special exit */
  }

  if (tr_mq_get_head(mq)!=NULL) {
    popped=tr_mq_get_head(mq);
    tr_mq_set_head(mq, tr_mq_msg_get_next(popped)); /* popped is the old head */

    if (tr_mq_get_head(mq)==NULL)
      tr_mq_set_tail(mq, NULL); /* just popped the last element */
  }
  tr_mq_unlock(mq);
  if (popped!=NULL)
    tr_mq_msg_set_next(popped, NULL); /* disconnect from list */
  return popped;
}

