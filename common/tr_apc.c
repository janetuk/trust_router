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
