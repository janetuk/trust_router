#ifndef _TRP_RTABLE_H_
#define _TRP_RTABLE_H_

#include <glib.h>
#include <talloc.h>
#include <time.h>

#include <trp_internal.h>

typedef struct trp_route {
  TR_NAME *apc;
  TR_NAME *realm;
  TR_NAME *peer;
  unsigned int metric;
  TR_NAME *trust_router;
  TR_NAME *next_hop;
  int selected;
  unsigned int interval; /* interval from route update */
  struct timespec *expiry;
  int local; /* is this a local route? */
  int triggered;
} TRP_ROUTE;

typedef GHashTable TRP_RTABLE;

TRP_RTABLE *trp_rtable_new(void);
void trp_rtable_free(TRP_RTABLE *rtbl);
void trp_rtable_add(TRP_RTABLE *rtbl, TRP_ROUTE *entry); /* adds or updates */
void trp_rtable_remove(TRP_RTABLE *rtbl, TRP_ROUTE *entry);
void trp_rtable_clear(TRP_RTABLE *rtbl);
size_t trp_rtable_size(TRP_RTABLE *rtbl);
size_t trp_rtable_apc_size(TRP_RTABLE *rtbl, TR_NAME *apc);
size_t trp_rtable_realm_size(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm);
TRP_ROUTE **trp_rtable_get_entries(TRP_RTABLE *rtbl, size_t *n_out);
TR_NAME **trp_rtable_get_apcs(TRP_RTABLE *rtbl, size_t *n_out);
TRP_ROUTE **trp_rtable_get_apc_entries(TRP_RTABLE *rtbl, TR_NAME *apc, size_t *n_out);
TR_NAME **trp_rtable_get_apc_realms(TRP_RTABLE *rtbl, TR_NAME *apc, size_t *n_out);
TRP_ROUTE **trp_rtable_get_realm_entries(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm, size_t *n_out);
TR_NAME **trp_rtable_get_apc_realm_peers(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm, size_t *n_out);
TRP_ROUTE *trp_rtable_get_entry(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm, TR_NAME *peer);
TRP_ROUTE *trp_rtable_get_selected_entry(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm);
void trp_rtable_clear_triggered(TRP_RTABLE *rtbl);
char *trp_rtable_to_str(TALLOC_CTX *mem_ctx, TRP_RTABLE *rtbl, const char *sep, const char *lineterm);

TRP_ROUTE *trp_route_new(TALLOC_CTX *mem_ctx);
void trp_route_free(TRP_ROUTE *entry);
void trp_route_set_apc(TRP_ROUTE *entry, TR_NAME *apc);
TR_NAME *trp_route_get_apc(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_apc(TRP_ROUTE *entry);
void trp_route_set_realm(TRP_ROUTE *entry, TR_NAME *realm);
TR_NAME *trp_route_get_realm(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_realm(TRP_ROUTE *entry);
void trp_route_set_trust_router(TRP_ROUTE *entry, TR_NAME *tr);
TR_NAME *trp_route_get_trust_router(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_trust_router(TRP_ROUTE *entry);
void trp_route_set_peer(TRP_ROUTE *entry, TR_NAME *peer);
TR_NAME *trp_route_get_peer(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_peer(TRP_ROUTE *entry);
void trp_route_set_metric(TRP_ROUTE *entry, unsigned int metric);
unsigned int trp_route_get_metric(TRP_ROUTE *entry);
void trp_route_set_next_hop(TRP_ROUTE *entry, TR_NAME *next_hop);
TR_NAME *trp_route_get_next_hop(TRP_ROUTE *entry);
TR_NAME *trp_route_dup_next_hop(TRP_ROUTE *entry);
void trp_route_set_selected(TRP_ROUTE *entry, int sel);
int trp_route_is_selected(TRP_ROUTE *entry);
void trp_route_set_interval(TRP_ROUTE *entry, int interval);
int trp_route_get_interval(TRP_ROUTE *entry);
void trp_route_set_expiry(TRP_ROUTE *entry, struct timespec *exp);
struct timespec *trp_route_get_expiry(TRP_ROUTE *entry);
void trp_route_set_local(TRP_ROUTE *entry, int local);
int trp_route_is_local(TRP_ROUTE *entry);
void trp_route_set_triggered(TRP_ROUTE *entry, int trig);
int trp_route_is_triggered(TRP_ROUTE *entry);
char *trp_route_to_str(TALLOC_CTX *mem_ctx, TRP_ROUTE *entry, const char *sep);

#endif /* _TRP_RTABLE_H_ */
