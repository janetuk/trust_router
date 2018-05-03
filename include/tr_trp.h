/*
 * Copyright (c) 2016, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef TR_TRP_H
#define TR_TRP_H

#include <event2/event.h>
#include <talloc.h>
#include <pthread.h>

#include <tr.h>
#include <trp_internal.h>
#include <tr_config.h>
#include <tr_cfgwatch.h>
#include <tr_event.h>
#include <mon_internal.h>

typedef struct tr_trps_events {
  struct event *trps_ev;
  struct tr_socket_event *listen_ev;
  struct event *mq_ev;
  struct event *connect_ev;
  struct event *update_ev;
  struct event *sweep_ev;
} TR_TRPS_EVENTS;

/* typedef'ed as TR_INSTANCE in tr.h */
struct tr_instance {
  TR_CFG_MGR *cfg_mgr;
  TIDS_INSTANCE *tids;
  TRPS_INSTANCE *trps;
  MONS_INSTANCE *mons;
  TR_CFGWATCH *cfgwatch;
  TR_TRPS_EVENTS *events;
};

/* messages between threads */
#define TR_MQMSG_MSG_RECEIVED "msg received"
#define TR_MQMSG_TRPC_DISCONNECTED "trpc disconnected"
#define TR_MQMSG_TRPC_CONNECTED "trpc connected"
#define TR_MQMSG_TRPS_DISCONNECTED "trps disconnected"
#define TR_MQMSG_TRPS_CONNECTED "trps connected"
#define TR_MQMSG_ABORT "abort"

/* prototypes */
TRP_RC tr_trps_event_init(struct event_base *base, struct tr_instance *tr);
TRP_RC tr_add_local_routes(TRPS_INSTANCE *trps, TR_CFG *cfg);
TRP_RC tr_trpc_initiate(TRPS_INSTANCE *trps, TRP_PEER *peer, struct event *ev);
void tr_config_changed(TR_CFG *new_cfg, void *cookie);
TRP_RC tr_connect_to_peers(TRPS_INSTANCE *trps, struct event *ev);
void tr_peer_status_change(TRP_PEER *peer, void *cookie);

/* tr_trp_mons.h */
void tr_trp_register_mons_handlers(TRPS_INSTANCE *trps, MONS_INSTANCE *mons);

#endif /* TR_TRP_H */
