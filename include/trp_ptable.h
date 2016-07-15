#ifndef _TRP_PTABLE_H_
#define _TRP_PTABLE_H_

#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>

typedef struct trp_peer TRP_PEER;
struct trp_peer {
  char *server;
  unsigned int port;
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
char *trp_ptable_to_str(TALLOC_CTX *memctx, TRP_PTABLE *ptbl, const char *sep, const char *lineterm);

TRP_PEER *trp_peer_new(TALLOC_CTX *memctx);
void trp_peer_free(TRP_PEER *peer);
char *trp_peer_get_server(TRP_PEER *peer);
void trp_peer_set_server(TRP_PEER *peer, char *server);
TR_NAME *trp_peer_get_gssname(TRP_PEER *peer);
unsigned int trp_peer_get_port(TRP_PEER *peer);
void trp_peer_set_port(TRP_PEER *peer, unsigned int port);
unsigned int trp_peer_get_linkcost(TRP_PEER *peer);
void trp_peer_set_linkcost(TRP_PEER *peer, unsigned int linkcost);
char *trp_peer_to_str(TALLOC_CTX *memctx, TRP_PEER *peer, const char *sep);

#endif /* _TRP_PTABLE_H_ */
