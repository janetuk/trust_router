#ifndef TR_TRP_H
#define TR_TRP_H

#include <talloc.h>

#include <trp_internal.h>
#include <tr_config.h>
#include <tr_event.h>

/* Data for a TRP peer */
typedef struct tr_trp_peer {
  TRPS_INSTANCE *trps; /* incoming connection, may be null */
  TRPC_INSTANCE *trpc; /* outgoing connection, may be null */
} TR_TRP_PEER;

/* prototypes */
int tr_trps_event_init(struct event_base *base, TRPS_INSTANCE *trps, TR_CFG_MGR *cfg_mgr,
                       struct tr_socket_event *trps_ev);

#endif /* TR_TRP_H */
