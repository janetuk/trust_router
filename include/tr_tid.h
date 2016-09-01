#ifndef TR_TID_H
#define TR_TID_H

#include <trp_internal.h>
#include <tr_event.h>
#include <tr_config.h>

int tr_tids_event_init(struct event_base *base,
                       TIDS_INSTANCE *tids,
                       TR_CFG_MGR *cfg_mgr,
                       TRPS_INSTANCE *trps,
                       struct tr_socket_event *tids_ev);

#endif /* TR_TID_H */
