#ifndef TR_TID_H
#define TR_TID_H

#include <tr.h>
#include <tr_event.h>

int tr_tids_event_init(struct event_base *base, TR_INSTANCE *tr, struct tr_socket_event *tids_ev);

#endif /* TR_TID_H */
