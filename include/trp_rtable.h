#ifndef _TRP_RTABLE_H_
#define _TRP_RTABLE_H_

#include <glib.h>
#include <talloc.h>
#include <time.h>

#include <trp_internal.h>

typedef struct trp_rentry {
  TR_NAME *apc;
  TR_NAME *realm;
  TR_NAME *trust_router;
  unsigned int metric;
  TR_NAME *peer;
  TR_NAME *next_hop;
  int selected;
  struct timespec *expiry;
} TRP_RENTRY;

typedef GHashTable TRP_RTABLE;

TRP_RTABLE *trp_rtable_new(void);
void trp_rtable_free(TRP_RTABLE *rtbl);
void trp_rtable_add(TRP_RTABLE *rtbl, TRP_RENTRY *entry); /* adds or updates */
void trp_rtable_remove(TRP_RTABLE *rtbl, TRP_RENTRY *entry);
size_t trp_rtable_get_apc(TRP_RTABLE *rtbl, TR_NAME *apc, TRP_RENTRY **ret); /* all entries in an apc */
size_t trp_rtable_get_realm(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm, TRP_RENTRY **ret); /* all entries in realm */
TRP_RENTRY *trp_rtable_get_entry(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm, TR_NAME *peer); /* single entry */

TRP_RENTRY *trp_rentry_new(TALLOC_CTX *mem_ctx);
void trp_rentry_free(TRP_RENTRY *entry);
void trp_rentry_set_apc(TRP_RENTRY *entry, TR_NAME *apc);
TR_NAME *trp_rentry_get_apc(TRP_RENTRY *entry);
void trp_rentry_set_realm(TRP_RENTRY *entry, TR_NAME *realm);
TR_NAME *trp_rentry_get_realm(TRP_RENTRY *entry);
void trp_rentry_set_trust_router(TRP_RENTRY *entry, TR_NAME *tr);
TR_NAME *trp_rentry_get_trust_router(TRP_RENTRY *entry);
void trp_rentry_set_peer(TRP_RENTRY *entry, TR_NAME *peer);
TR_NAME *trp_rentry_get_peer(TRP_RENTRY *entry);
void trp_rentry_set_metric(TRP_RENTRY *entry, unsigned int metric);
unsigned int trp_rentry_get_metric(TRP_RENTRY *entry);
void trp_rentry_set_next_hop(TRP_RENTRY *entry, TR_NAME *next_hop);
TR_NAME *trp_rentry_get_next_hop(TRP_RENTRY *entry);
void trp_rentry_set_selected(TRP_RENTRY *entry, int sel);
int trp_rentry_get_selected(TRP_RENTRY *entry);
void trp_rentry_set_expiry(TRP_RENTRY *entry, struct timespec *exp);
struct timespec *trp_rentry_get_expiry(TRP_RENTRY *entry);

#endif /* _TRP_RTABLE_H_ */
