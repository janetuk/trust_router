#ifndef TR_TRP_H
#define TR_TRP_H

#include <event2/event.h>
#include <talloc.h>
#include <pthread.h>

#include <trp_internal.h>
#include <tr_config.h>
#include <tr_event.h>

typedef struct tr_trps_events {
  struct tr_socket_event *listen_ev;
  struct event *mq_ev;
  struct event *update_ev;
  struct event *sweep_ev;
} TR_TRPS_EVENTS;

/* prototypes */
TR_TRPS_EVENTS *tr_trps_events_new(TALLOC_CTX *mem_ctx);
TRP_RC tr_trps_event_init(struct event_base *base, TRPS_INSTANCE *trps, TR_CFG_MGR *cfg_mgr,
                       TR_TRPS_EVENTS *trps_ev);
TRPC_INSTANCE *tr_trpc_initiate(TRPS_INSTANCE *trps, const char *server, unsigned int port);
void tr_config_changed(TR_CFG *new_cfg, void *cookie);
#endif /* TR_TRP_H */
