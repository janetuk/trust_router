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

#ifndef _TR_MQ_H_
#define _TR_MQ_H_

#include <talloc.h>
#include <pthread.h>

/* Note on mq priorities: High priority messages are guaranteed to be
 * processed before any normal priority messages. Otherwise, messages
 * will be processed in the order they are added to the queue. */

typedef enum tr_mq_priority {
  TR_MQ_PRIO_NORMAL=0,
  TR_MQ_PRIO_HIGH
} TR_MQ_PRIORITY;

/* msg for inter-thread messaging */
typedef struct tr_mq_msg TR_MQ_MSG;
struct tr_mq_msg {
  TR_MQ_MSG *next;
  TR_MQ_PRIORITY prio;
  char *message;
  void *p; /* payload */
  void (*p_free)(void *); /* function to free payload */
};

/* message queue for inter-thread messaging */

typedef struct tr_mq TR_MQ;
typedef void (*TR_MQ_NOTIFY_FN)(TR_MQ *, void *);
struct tr_mq {
  pthread_mutex_t mutex;
  TR_MQ_MSG *head;
  TR_MQ_MSG *tail;
  TR_MQ_MSG *last_hi_prio;
  TR_MQ_NOTIFY_FN notify_cb; /* callback when queue becomes non-empty */
  void *notify_cb_arg;
};

/* message string for sending trpc messages */
#define TR_MQMSG_TRPC_SEND "trpc send msg"

TR_MQ_MSG *tr_mq_msg_new(TALLOC_CTX *mem_ctx, const char *msg, TR_MQ_PRIORITY prio);
void tr_mq_msg_free(TR_MQ_MSG *msg);
TR_MQ_PRIORITY tr_mq_msg_get_prio(TR_MQ_MSG *msg);
const char *tr_mq_msg_get_message(TR_MQ_MSG *msg);
void *tr_mq_msg_get_payload(TR_MQ_MSG *msg);
void tr_mq_msg_set_payload(TR_MQ_MSG *msg, void *p, void (*p_free)(void *));


TR_MQ *tr_mq_new(TALLOC_CTX *mem_ctx);
void tr_mq_free(TR_MQ *mq);
int tr_mq_lock(TR_MQ *mq);
int tr_mq_unlock(TR_MQ *mq);
void tr_mq_set_notify_cb(TR_MQ *mq, TR_MQ_NOTIFY_FN cb, void *arg);
void tr_mq_add(TR_MQ *mq, TR_MQ_MSG *msg);
TR_MQ_MSG *tr_mq_pop(TR_MQ *mq);
void tr_mq_clear(TR_MQ *mq);
 
#endif /*_TR_MQ_H_ */
