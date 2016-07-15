#include <talloc.h>

#include <tr_name.h>
#include <trp_internal.h>
#include <trp_ptable.h>

static int trp_peer_destructor(void *object)
{
  TRP_PEER *peer=talloc_get_type_abort(object, TRP_PEER);

  if (peer->gssname != NULL) {
    tr_free_name(peer->gssname);
  }
  return 0;
}

TRP_PTABLE *trp_peer_new(TALLOC_CTX *memctx)
{
  TRP_PEER *peer=talloc(memctx, TRP_PEER);
  if (peer!=NULL) {
    peer->gssname=NULL;
    peer->linkcost=TRP_METRIC_INFINITY;
    peer->next=NULL;
    talloc_set_destructor((void *)peer, trp_peer_destructor);
  }
  return peer;
}

void trp_peer_free(TRP_PEER *peer)
{
  talloc_free(peer);
}

static TRP_PEER trp_peer_tail(TRP_PEER *peer)
{
  while (peer->next!=NULL) {
    peer=peer->next;
  }
  return peer;
}


TRP_PTABLE *trp_ptable_new(TALLOC_CTX *memctx)
{
  TRP_PTABLE *ptbl=talloc(memctx, TRP_PTABLE);
  if (ptbl!=NULL) {
    ptbl->head=NULL;
  }
  return ptbl;
}

void trp_ptable_free(TRP_PTABLE *ptbl)
{
  talloc_free(ptbl);
}

TRP_RC trp_ptable_add(TRP_PTABLE *ptbl, TRP_PEER *newpeer)
{
  if (ptbl->head==NULL) {
    ptbl->head=newpeer;
  } else {
    trp_peer_tail(ptbl->head)->next=newpeer;
    talloc_steal(ptbl, newpeer);
  }
  return TRP_SUCCESS;
}

/* peer pointer is invalid after successful removal. Does nothing and returns
 * TRP_ERROR if peer is not in the list. */
TRP_RC trp_ptable_remove(TRP_PTABLE *ptbl, TRP_PEER *peer)
{
  TRP_PEER *cur=NULL;
  TRP_PEER *last=NULL;
  if (ptbl->head!=NULL) {
    if (ptbl->head==peer) {
      /* special case for removing head of list */
      cur=ptbl->head;
      ptbl->head=ptbl->head->next; /* advance the head */
      trp_peer_free(cur);
    }
    for (cur=ptbl->head->next; cur!=NULL; last=cur,cur=cur->next) {
      if (cur==peer) {
        if (last!=NULL)
          last->next=cur->next;
        trp_peer_free(cur);
        return TRP_SUCCESS;
      }
    }
  }
  return TRP_ERROR;
}

