#include <talloc.h>
#include <pthread.h>

#include <tr_mq.h>

/* Messages */
static int tr_mq_msg_destructor(void *object)
{
  TR_MQ_MSG *msg=talloc_get_type_abort(object, TR_MQ_MSG);
  if ( (msg->p!=NULL) && (msg->p_free!=NULL))
    msg->p_free(msg->p);
  return 0;
}

TR_MQ_MSG *tr_mq_msg_new(TALLOC_CTX *mem_ctx)
{
  TR_MQ_MSG *msg=talloc(mem_ctx, TR_MQ_MSG);
  if (msg!=NULL) {
    msg->next=NULL;
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

static TR_MQ_MSG *tr_mq_msg_get_tail(TR_MQ_MSG *msg)
{
  while (msg!=NULL)
    msg=tr_mq_msg_get_next(msg);
  return msg;
}

static void tr_mq_msg_append(TR_MQ_MSG *msg, TR_MQ_MSG *new)
{
  tr_mq_msg_set_next(tr_mq_msg_get_tail(msg), new);
}

/* Message Queues */
TR_MQ *tr_mq_new(TALLOC_CTX *mem_ctx)
{
  TR_MQ *mq=talloc(mem_ctx, TR_MQ);
  if (mq!=NULL) {
    pthread_mutex_init(&(mq->mutex), 0);
    mq->head=NULL;
    mq->tail=NULL;
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
  return pthread_mutex_lock(&(mq->mutex));
}

static TR_MQ_MST *tr_mq_get_head(TR_MQ *mq)
{
  return mq->head;
}

static void tr_mq_set_head(TR_MQ *mq, TR_MQ_MSG *msg)
{
  mq->head=msg;
}

static TR_MQ_MST *tr_mq_get_tail(TR_MQ *mq)
{
  return mq->tail;
}

static void tr_mq_set_tail(TR_MQ *mq, TR_MQ_MSG *msg)
{
  mq->tail=msg;
}

/* puts msg in mq's talloc context */
void tr_mq_append(TR_MQ *mq, TR_MQ_MSG *msg)
{
  int was_empty=FALSE;
  TR_MQ_NOTIFY_FN notify_cb=NULL;
  void *notify_cb_arg=NULL;

  tr_mq_lock(mq);
  if (tr_mq_get_head(mq)==NULL) {
    was_empty=TRUE;
    tr_mq_set_head(mq, msg);
    tr_mq_set_tail(mq, msg);
  } else {
    tr_mq_msg_set_next(tr_mq_get_tail(), msg); /* add to list */
    tr_mq_set_tail(mq, msg); /* update tail of list */
  }
  talloc_steal(mq, msg);
  /* before releasing the mutex, get notify_cb data out of mq */
  notify_cb=mq->notify_cb;
  notify_cb_arg=mq->notify_cb_arg;
  tr_mq_unlock(mq);

  /* see if we need to tell someone we became non-empty */
  if (was_empty && (notify_cb!=NULL))
    mq->notify_cb(mq, notify_cb_arg);
}

/* caller must free msg via tr_mq_msg_free */
TR_MQ_MSG *tr_mq_pop(TR_MQ *mq)
{
  TR_MQ_MSG *popped=NULL;

  tr_mq_lock(mq);
  if (tr_mq_get_head(mq)!=NULL) {
    popped=tr_mq_get_head(mq);
    tr_mq_msg_set_next(popped, tr_mq_msg_get_next(popped)); /* popped is the old head */
    if (tr_mq_get_head(mq)==NULL)
      tr_mq_set_tail(mq, NULL); /* just popped the last element */
  }
  tr_mq_unlock(mq);
  if (popped!=NULL)
    tr_mq_msg_set_next(popped, NULL); /* disconnect from list */
  return popped;
}
