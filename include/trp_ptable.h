#ifndef _TRP_PTABLE_H_
#define _TRP_PTABLE_H_

#include <time.h>
#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>

typedef enum trp_peer_conn_status {
  PEER_DISCONNECTED=0,
  PEER_CONNECTED
} TRP_PEER_CONN_STATUS;

typedef struct trp_peer TRP_PEER;
struct trp_peer {
  TRP_PEER *next; /* for making a linked list */
  char *server;
  TR_NAME *gssname;
  TR_NAME *servicename;
  unsigned int port;
  unsigned int linkcost;
  struct timespec last_conn_attempt;
  TRP_PEER_CONN_STATUS outgoing_status;
  TRP_PEER_CONN_STATUS incoming_status;
  void (*conn_status_cb)(TRP_PEER *, void *); /* callback for connected status change */
  void *conn_status_cookie;
};

typedef struct trp_ptable {
  TRP_PEER *head; /* head of a peer table list */
} TRP_PTABLE;

/* iterator for the peer table */
typedef TRP_PEER *TRP_PTABLE_ITER;

TRP_PTABLE *trp_ptable_new(TALLOC_CTX *memctx);
void trp_ptable_free(TRP_PTABLE *ptbl);
TRP_RC trp_ptable_add(TRP_PTABLE *ptbl, TRP_PEER *newpeer);
TRP_RC trp_ptable_remove(TRP_PTABLE *ptbl, TRP_PEER *peer);
TRP_PEER *trp_ptable_find_gssname(TRP_PTABLE *ptbl, TR_NAME *gssname);
TRP_PEER *trp_ptable_find_servicename(TRP_PTABLE *ptbl, TR_NAME *servicename);
char *trp_ptable_to_str(TALLOC_CTX *memctx, TRP_PTABLE *ptbl, const char *sep, const char *lineterm);

TRP_PTABLE_ITER *trp_ptable_iter_new(TALLOC_CTX *mem_ctx);
TRP_PEER *trp_ptable_iter_first(TRP_PTABLE_ITER *iter, TRP_PTABLE *ptbl);
TRP_PEER *trp_ptable_iter_next(TRP_PTABLE_ITER *iter);
void trp_ptable_iter_free(TRP_PTABLE_ITER *iter);

TRP_PEER *trp_peer_new(TALLOC_CTX *memctx);
void trp_peer_free(TRP_PEER *peer);
char *trp_peer_get_server(TRP_PEER *peer);
void trp_peer_set_server(TRP_PEER *peer, char *server);
void trp_peer_set_gssname(TRP_PEER *peer, TR_NAME *gssname);
TR_NAME *trp_peer_get_gssname(TRP_PEER *peer);
TR_NAME *trp_peer_dup_gssname(TRP_PEER *peer);
TR_NAME *trp_peer_get_servicename(TRP_PEER *peer);
TR_NAME *trp_peer_dup_servicename(TRP_PEER *peer);
unsigned int trp_peer_get_port(TRP_PEER *peer);
void trp_peer_set_port(TRP_PEER *peer, unsigned int port);
unsigned int trp_peer_get_linkcost(TRP_PEER *peer);
struct timespec *trp_peer_get_last_conn_attempt(TRP_PEER *peer);
void trp_peer_set_last_conn_attempt(TRP_PEER *peer, struct timespec *time);
TRP_PEER_CONN_STATUS trp_peer_get_outgoing_status(TRP_PEER *peer);
void trp_peer_set_outgoing_status(TRP_PEER *peer, TRP_PEER_CONN_STATUS status);
TRP_PEER_CONN_STATUS trp_peer_get_incoming_status(TRP_PEER *peer);
void trp_peer_set_incoming_status(TRP_PEER *peer, TRP_PEER_CONN_STATUS status);
int trp_peer_is_connected(TRP_PEER *peer);
void trp_peer_set_linkcost(TRP_PEER *peer, unsigned int linkcost);
void trp_peer_set_conn_status_cb(TRP_PEER *peer, void (*cb)(TRP_PEER *, void *), void *cookie);
char *trp_peer_to_str(TALLOC_CTX *memctx, TRP_PEER *peer, const char *sep);

#endif /* _TRP_PTABLE_H_ */
