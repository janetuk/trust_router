#include <talloc.h>

#include <trust_router/tr_name.h>
#include <tr_apc.h>

static int tr_apc_destructor(void *obj)
{
  TR_APC *apc=talloc_get_type_abort(obj, TR_APC);
  if (apc->id!=NULL)
    tr_free_name(apc->id);
  return 0;
}

TR_APC *tr_apc_new(TALLOC_CTX *mem_ctx)
{
  TR_APC *apc=talloc(mem_ctx, TR_APC);
  if (apc!=NULL) {
    apc->id=NULL;
    apc->next=NULL;
    talloc_set_destructor((void *)apc, tr_apc_destructor);
  }
  return apc;
}

void tr_apc_free(TR_APC *apc)
{
  talloc_free(apc);
}

static TR_APC *tr_apc_tail(TR_APC *apc)
{
  if (apc==NULL)
    return NULL;

  while (apc->next!=NULL)
    apc=apc->next;
  return apc;
}

TR_APC *tr_apc_add(TR_APC *head, TR_APC *new)
{
  if (head==NULL)
    head=new;
  else {
    tr_apc_tail(head)->next=new;
    while (new!=NULL) {
      talloc_steal(head, new);
      new=new->next;
    }
  }
  return head;
}

/* does not copy next pointer */
TR_APC *tr_apc_dup(TALLOC_CTX *mem_ctx, TR_APC *apc)
{
  TR_APC *new=tr_apc_new(mem_ctx);
  tr_apc_set_id(new, tr_apc_dup_id(apc));
  return new;
}

void tr_apc_set_id(TR_APC *apc, TR_NAME *id)
{
  if (apc->id)
    tr_free_name(apc->id);
  apc->id=id;
}

TR_NAME *tr_apc_get_id(TR_APC *apc)
{
  return apc->id;
}

TR_NAME *tr_apc_dup_id(TR_APC *apc)
{
  return tr_dup_name(apc->id);;
}
