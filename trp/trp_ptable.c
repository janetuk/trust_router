#include <time.h>
#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <trp_ptable.h>
#include <tr_debug.h>

static int trp_peer_destructor(void *object)
{
  TRP_PEER *peer=talloc_get_type_abort(object, TRP_PEER);
  if (peer->gssname!=NULL)
    tr_free_name(peer->gssname);
  return 0;
}
TRP_PEER *trp_peer_new(TALLOC_CTX *memctx)
{
  TRP_PEER *peer=talloc(memctx, TRP_PEER);
  if (peer!=NULL) {
    peer->next=NULL;
    peer->server=NULL;
    peer->gssname=NULL;
    peer->port=0;
    peer->linkcost=TRP_LINKCOST_DEFAULT;
    peer->last_conn_attempt=(struct timespec){0,0};
    talloc_set_destructor((void *)peer, trp_peer_destructor);
  }
  return peer;
}

void trp_peer_free(TRP_PEER *peer)
{
  talloc_free(peer);
}

static TRP_PEER *trp_peer_tail(TRP_PEER *peer)
{
  while (peer->next!=NULL) {
    peer=peer->next;
  }
  return peer;
}

char *trp_peer_get_server(TRP_PEER *peer)
{
  return peer->server;
}

/* copies input; on error, peer->gssname will be null */
void trp_peer_set_server(TRP_PEER *peer, char *server)
{
  peer->server=talloc_strdup(peer, server); /* will be null on error */
}

void trp_peer_set_gssname(TRP_PEER *peer, TR_NAME *gssname)
{
  peer->gssname=gssname;
}

/* get the peer gssname, caller must not free the result */
TR_NAME *trp_peer_get_gssname(TRP_PEER *peer)
{
  return peer->gssname;
}

/* get a copy of the peer gssname, caller must free via tr_free_name() */
TR_NAME *trp_peer_dup_gssname(TRP_PEER *peer)
{
  return tr_dup_name(peer->gssname);
}

unsigned int trp_peer_get_port(TRP_PEER *peer)
{
  return peer->port;
}

void trp_peer_set_port(TRP_PEER *peer, unsigned int port)
{
  peer->port=port;
}

unsigned int trp_peer_get_linkcost(TRP_PEER *peer)
{
  if (peer!=NULL)
    return peer->linkcost;
  else
    return 1;
}

void trp_peer_set_linkcost(TRP_PEER *peer, unsigned int linkcost)
{
  if ((linkcost>TRP_METRIC_INFINITY) && (linkcost!=TRP_METRIC_INVALID)) {
    /* This indicates a programming error, but probably means an already infinite metric
     * was (incorrectly) incremented. Issue a warning and proceed with an infinite metric. */
    tr_warning("trp_peer_set_linkcost: link cost > infinity encountered, setting to infinity");
    linkcost=TRP_METRIC_INFINITY;
  }
  peer->linkcost=linkcost;
}

struct timespec *trp_peer_get_last_conn_attempt(TRP_PEER *peer)
{
  return &(peer->last_conn_attempt);
}

void trp_peer_set_last_conn_attempt(TRP_PEER *peer, struct timespec *time)
{
  peer->last_conn_attempt=*time;
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

TRP_PEER *trp_ptable_find(TRP_PTABLE *ptbl, TR_NAME *gssname)
{
  TRP_PEER *cur=ptbl->head;
  while ((cur!=NULL) && (0 != tr_name_cmp(trp_peer_get_gssname(cur), gssname)))
    cur=cur->next;
  return cur;
}

char *trp_peer_to_str(TALLOC_CTX *memctx, TRP_PEER *peer, const char *sep)
{
  if (sep==NULL)
    sep=", ";
  return talloc_asprintf(memctx,
                         "%s:%u%s0x%04X",
                         peer->server, peer->port, sep,
                         peer->linkcost);
}

/* this is horribly inefficient but should be ok for small peer tables */
char *trp_ptable_to_str(TALLOC_CTX *memctx, TRP_PTABLE *ptbl, const char *sep, const char *lineterm)
{
  TALLOC_CTX *tmpctx=talloc_new(NULL);
  TRP_PEER *peer=NULL;
  char *result=talloc_strdup(tmpctx, "");

  if (lineterm==NULL)
    lineterm="\n";

  /* this leaves intermediate result strings in the tmpctx context, we'll free these when
   * we're done */
  for (peer=ptbl->head; peer!=NULL; peer=peer->next)
    result=talloc_asprintf(tmpctx, "%s%s%s", result, lineterm, trp_peer_to_str(tmpctx, peer, sep));

  talloc_steal(memctx, result); /* hand result over to caller */
  talloc_free(tmpctx); /* free detritus */
  return result;
}

TRP_PTABLE_ITER *trp_ptable_iter_new(TALLOC_CTX *mem_ctx)
{
  TRP_PTABLE_ITER *iter=talloc(mem_ctx, TRP_PTABLE_ITER);
  *iter=NULL;
  return iter;
}

TRP_PEER *trp_ptable_iter_first(TRP_PTABLE_ITER *iter, TRP_PTABLE *ptbl)
{
  *iter=ptbl->head;
  return *iter;
}

TRP_PEER *trp_ptable_iter_next(TRP_PTABLE_ITER *iter)
{
  *iter=(*iter)->next;
  return *iter;
}

void trp_ptable_iter_free(TRP_PTABLE_ITER *iter)
{
  talloc_free(iter);
}

