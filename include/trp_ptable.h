#ifndef _TRP_PTABLE_H_
#define _TRP_PTABLE_H_

#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>

typedef struct trp_peer TRP_PEER;
struct trp_peer {
  TR_NAME *gssname;
  unsigned int linkcost;
  TRP_PEER *next; /* for making a linked list */
};

typedef struct trp_ptable {
  TRP_PEER *head; /* head of a peer table list */
} TRP_PTABLE;

TRP_PTABLE *trp_ptable_new(TALLOC_CTX *memctx);
void trp_ptable_free(TRP_PTABLE *ptbl);
TRP_RC trp_ptable_add(TRP_PTABLE *ptbl, TRP_PEER *newpeer);
TRP_RC trp_ptable_remove(TRP_PTABLE *ptbl, TRP_PEER *peer);

TRP_PEER *trp_peer_new(TALLOC_CTX *memctx);
void trp_peer_free(TRP_PEER *peer);

#endif /* _TRP_PTABLE_H_ */
