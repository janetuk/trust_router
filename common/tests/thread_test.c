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
#include <unistd.h>
#include <pthread.h>
#include <talloc.h>
#include <time.h>
#include <errno.h>
#include <assert.h>

#include <tr_mq.h>

struct thread_data {
  TR_MQ *mq;
  useconds_t msg_dly;
  int n_msgs;
  char *label;
};

static TR_MQ_MSG *make_msg(char *label, int n)
{
  TR_MQ_MSG *msg=NULL;
  msg= tr_mq_msg_new(NULL, "Message");
  assert(-1!=asprintf((char **)&(msg->p), "%s: %d messages to go...", label, n));
  msg->p_free=free;
  return msg;
}

static void *thread_start(void *arg)
{
  TR_MQ *mq=((struct thread_data *)arg)->mq;
  int n_msgs=((struct thread_data *)arg)->n_msgs;
  useconds_t msg_dly=((struct thread_data *)arg)->msg_dly;
  char *label=((struct thread_data *)arg)->label;
  
  while (n_msgs>=0) {
    usleep(msg_dly);
    tr_mq_add(mq, make_msg(label, n_msgs));
    n_msgs--;
  }
  tr_mq_add(mq, make_msg(label, -9999));
  return NULL;
}

struct message_data {
  pthread_mutex_t lock;
  pthread_cond_t cond;
  int ready;
};

static void handle_messages(TR_MQ *mq, void *arg)
{
  struct message_data *status=(struct message_data *)arg;
  pthread_mutex_lock(&(status->lock));
  status->ready=1;
  pthread_cond_signal(&(status->cond));
  pthread_mutex_unlock(&(status->lock));
}

static void output_messages(TR_MQ *mq)
{
  TR_MQ_MSG *msg=NULL;

  printf("\n* handle_messages notified of new messages in queue.\n");
  for (msg=tr_mq_pop(mq, NULL); msg!=NULL; msg=tr_mq_pop(mq, NULL)) {
    printf("  > %s\n", (char *)msg->p);
    tr_mq_msg_free(msg);
  }
  printf("* all messages handled\n");
  fflush(stdout);
}

#define N_THREADS 2

int main(void)
{
  TR_MQ *mq=NULL;
  pthread_t thread[N_THREADS];
  struct thread_data thread_data[N_THREADS];
  useconds_t dly[N_THREADS]={100000, 1000000}; /* must be N_THREADS long */
  int ii=0;
  struct message_data status;
  struct timespec timeout={0,0};
  int wait_result=0;

  mq=tr_mq_new(NULL);
  mq->notify_cb=handle_messages;
  mq->notify_cb_arg=(void *)&status;

  pthread_cond_init(&(status.cond), 0);
  pthread_mutex_init(&(status.lock), 0);
  status.ready=0;

  printf("Starting threads\n");
  for (ii=0; ii<N_THREADS; ii++) {
    thread_data[ii].mq=mq;
    thread_data[ii].msg_dly=dly[ii];
    thread_data[ii].n_msgs=10;
    assert(-1!=asprintf(&(thread_data[ii].label), "thread %d", ii+1));
    pthread_create(&(thread[ii]), NULL, thread_start, &thread_data[ii]);
    printf("%s started.\n", thread_data[ii].label);
  }

  while (1) {
    pthread_mutex_lock(&(status.lock));
    while ((!status.ready) && (wait_result!=ETIMEDOUT)) {
      clock_gettime(CLOCK_REALTIME, &timeout);
      timeout.tv_sec+=1;
      wait_result=pthread_cond_timedwait(&(status.cond), &(status.lock), &timeout);
    }

    if (wait_result==ETIMEDOUT)
      break;

    output_messages(mq);
    status.ready=0;
    pthread_mutex_unlock(&(status.lock));
    usleep(2000000);
  }
  printf("\n*** Timeout expired with no new messages. Joining threads and terminating.\n");
  for (ii=0; ii<N_THREADS; ii++)
    pthread_join(thread[ii], NULL);

  printf("success\n");
  return 0;
}
