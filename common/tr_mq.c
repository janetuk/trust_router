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

/* Message Queues */
TR_MQ *tr_mq_new(TALLOC_CTX *mem_ctx)
{
  TR_MQ *mq=talloc(mem_ctx, TR_MQ);
  if (mq!=NULL) {
    pthread_mutex_init(&(mq->lock), 0);
    mq->head=NULL;
    mq->tail=NULL;
  }
  return mq;
}

void tr_mq_free(TR_MQ *mq)
{
  if (mq!=NULL) {
    pthread_mutex_lock(&(mq->lock)); /* don't pull this out from under someone */
    talloc_free(mq);
  }
}

/* puts msg in mq's talloc context */
void tr_mq_append(TR_MQ *mq, TR_MQ_MSG *msg)
{
  int was_empty=FALSE;
  TR_MQ_NOTIFY_FN notify_cb=NULL;
  void *notify_cb_arg=NULL;

  pthread_mutex_lock(&(mq->lock));
  if (mq->head==NULL) {
    was_empty=TRUE;
    mq->head=mq->tail=msg;
  } else {
    mq->tail->next=msg; /* add to list */
    mq->tail=msg; /* update tail of list */
  }
  talloc_steal(mq, msg);
  /* before releasing the lock, get notify_cb data out of mq */
  notify_cb=mq->notify_cb;
  notify_cb_arg=mq->notify_cb_arg;
  pthread_mutex_unlock(&(mq->lock));

  /* see if we need to tell someone we became non-empty */
  if (was_empty && (notify_cb!=NULL))
    mq->notify_cb(mq, notify_cb_arg);
}

/* caller must free msg via tr_mq_msg_free */
TR_MQ_MSG *tr_mq_pop(TR_MQ *mq)
{
  TR_MQ_MSG *popped=NULL;

  pthread_mutex_lock(&(mq->lock));
  if (mq->head!=NULL) {
    popped=mq->head;
    mq->head=mq->head->next;
    if (mq->head==NULL)
      mq->tail=NULL; /* just popped the last element */
  }
  pthread_mutex_unlock(&(mq->lock));
  if (popped!=NULL)
    popped->next=NULL; /* disconnect */
  return popped;
}
