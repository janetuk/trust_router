#ifndef _TR_MQ_H_
#define _TR_MQ_H_

#include <talloc.h>
#include <pthread.h>

/* msg for inter-thread messaging */
typedef struct tr_mq_msg TR_MQ_MSG;
struct tr_mq_msg {
  TR_MQ_MSG *next;
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
  TR_MQ_NOTIFY_FN notify_cb; /* callback when queue becomes non-empty */
  void *notify_cb_arg;
};

TR_MQ_MSG *tr_mq_msg_new(TALLOC_CTX *mem_ctx);
void tr_mq_msg_free(TR_MQ_MSG *msg);
void *tr_mq_msg_get_payload(TR_MQ_MSG *msg);
void tr_mq_msg_set_payload(TR_MQ_MSG *msg, void *p, void (*p_free)(void *));


TR_MQ *tr_mq_new(TALLOC_CTX *mem_ctx);
void tr_mq_free(TR_MQ *mq);
int tr_mq_lock(TR_MQ *mq);
int tr_mq_unlock(TR_MQ *mq);
void tr_mq_set_notify_cb(TR_MQ *mq, TR_MQ_NOTIFY_FN cb, void *arg);
void tr_mq_append(TR_MQ *mq, TR_MQ_MSG *msg);
TR_MQ_MSG *tr_mq_pop(TR_MQ *mq);
 
#endif /*_TR_MQ_H_ */
