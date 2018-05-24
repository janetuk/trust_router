/*
 * Copyright (c) 2016-2018, JANET(UK)
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

#include <stdlib.h>

#include <glib.h>
#include <talloc.h>
#include <time.h>

#include <tr_name_internal.h>
#include <trp_route.h>
#include <trp_internal.h>
#include <trp_rtable.h>
#include <tr_debug.h>
#include <trust_router/trp.h>
#include <trust_router/tid.h>
#include <tr_util.h>


/* Note: be careful mixing talloc with glib. */

static int trp_route_destructor(void *obj)
{
  TRP_ROUTE *entry=talloc_get_type_abort(obj, TRP_ROUTE);
  if (entry->comm!=NULL)
    tr_free_name(entry->comm);
  if (entry->realm!=NULL)
    tr_free_name(entry->realm);
  if (entry->trust_router!=NULL)
    tr_free_name(entry->trust_router);
  if (entry->peer!=NULL)
    tr_free_name(entry->peer);
  if (entry->next_hop!=NULL)
    tr_free_name(entry->next_hop);
  return 0;
}

TRP_ROUTE *trp_route_new(TALLOC_CTX *mem_ctx)
{
  TRP_ROUTE *entry=talloc(mem_ctx, TRP_ROUTE);
  if (entry!=NULL) {
    entry->comm=NULL;
    entry->realm=NULL;
    entry->trust_router=NULL;
    entry->trust_router_port=TRP_PORT;
    entry->next_hop_port=TID_PORT;
    entry->peer=NULL;
    entry->next_hop=NULL;
    entry->selected=0;
    entry->interval=0;
    entry->expiry=talloc(entry, struct timespec);
    if (entry->expiry==NULL) {
      talloc_free(entry);
      return NULL;
    }
    *(entry->expiry)=(struct timespec){0,0};
    entry->local=0;
    entry->triggered=0;
    talloc_set_destructor((void *)entry, trp_route_destructor);
  }
  return entry;
}

void trp_route_free(TRP_ROUTE *entry)
{
  if (entry!=NULL)
    talloc_free(entry);
}

void trp_route_set_comm(TRP_ROUTE *entry, TR_NAME *comm)
{
  if (entry->comm!=NULL)
    tr_free_name(entry->comm);
  entry->comm=comm;
}

TR_NAME *trp_route_get_comm(TRP_ROUTE *entry)
{
  return entry->comm;
}

TR_NAME *trp_route_dup_comm(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_comm(entry));
}

void trp_route_set_realm(TRP_ROUTE *entry, TR_NAME *realm)
{
  if (entry->realm!=NULL)
    tr_free_name(entry->realm);
  entry->realm=realm;
}

TR_NAME *trp_route_get_realm(TRP_ROUTE *entry)
{
  return entry->realm;
}

TR_NAME *trp_route_dup_realm(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_realm(entry));
}

void trp_route_set_trust_router(TRP_ROUTE *entry, TR_NAME *tr)
{
  if (entry->trust_router!=NULL)
    tr_free_name(entry->trust_router);
  entry->trust_router=tr;
}

TR_NAME *trp_route_get_trust_router(TRP_ROUTE *entry)
{
  return entry->trust_router;
}

TR_NAME *trp_route_dup_trust_router(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_trust_router(entry));
}

void trp_route_set_peer(TRP_ROUTE *entry, TR_NAME *peer)
{
  if (entry->peer!=NULL)
    tr_free_name(entry->peer);
  entry->peer=peer;
}

TR_NAME *trp_route_get_peer(TRP_ROUTE *entry)
{
  return entry->peer;
}

TR_NAME *trp_route_dup_peer(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_peer(entry));
}

void trp_route_set_metric(TRP_ROUTE *entry, unsigned int metric)
{
  entry->metric=metric;
}

unsigned int trp_route_get_metric(TRP_ROUTE *entry)
{
  return entry->metric;
}

/* TODO: set the hostname and port for the next hop. Currently assume default TID port. --jlr */
void trp_route_set_next_hop(TRP_ROUTE *entry, TR_NAME *next_hop)
{
  if (entry->next_hop!=NULL)
    tr_free_name(entry->next_hop);
  entry->next_hop=next_hop;
}

TR_NAME *trp_route_get_next_hop(TRP_ROUTE *entry)
{
  return entry->next_hop;
}

TR_NAME *trp_route_dup_next_hop(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_next_hop(entry));
}

void trp_route_set_selected(TRP_ROUTE *entry, int sel)
{
  entry->selected=sel;
}

int trp_route_is_selected(TRP_ROUTE *entry)
{
  return entry->selected;
}

void trp_route_set_interval(TRP_ROUTE *entry, int interval)
{
  entry->interval=interval;
}

int trp_route_get_interval(TRP_ROUTE *entry)
{
  return entry->interval;
}

/* copies incoming value, does not assume responsibility for freeing */
void trp_route_set_expiry(TRP_ROUTE *entry, struct timespec *exp)
{
  entry->expiry->tv_sec=exp->tv_sec;
  entry->expiry->tv_nsec=exp->tv_nsec;
}

struct timespec *trp_route_get_expiry(TRP_ROUTE *entry)
{
  return entry->expiry;
}

/**
 * Get the expiration according to the realtime clock
 *
 * @param entry
 * @param result space to store the result
 * @return pointer to the result, or null on error
 */
struct timespec *trp_route_get_expiry_realtime(TRP_ROUTE *entry, struct timespec *result)
{
  return tr_clock_convert(TRP_CLOCK, entry->expiry, CLOCK_REALTIME, result);
}

void trp_route_set_local(TRP_ROUTE *entry, int local)
{
  entry->local=local;
}

int trp_route_is_local(TRP_ROUTE *entry)
{
  return entry->local;
}

void trp_route_set_triggered(TRP_ROUTE *entry, int trig)
{
  tr_debug("trp_route_set_triggered: setting route to %.*s/%.*s through %.*s to %s",
           entry->comm->len, entry->comm->buf,
           entry->realm->len, entry->realm->buf,
           entry->peer->len, entry->peer->buf,
           trig ? "triggered" : "not triggered");
  entry->triggered=trig;
}

int trp_route_is_triggered(TRP_ROUTE *entry)
{
  return entry->triggered;
}

void trp_route_set_trust_router_port(TRP_ROUTE *entry, int port)
{
  if (entry)
    entry->trust_router_port = port;
}

/**
 * Get the port to use for TRP connections to the trust router
 *
 * @param entry
 * @return port, or -1 if entry is null
 */
int trp_route_get_trust_router_port(TRP_ROUTE *entry)
{
  if (entry)
    return entry->trust_router_port;

  return -1;
}

void trp_route_set_next_hop_port(TRP_ROUTE *entry, int port)
{
  if (entry)
    entry->next_hop_port = port;
}

/**
 * Get the port to use for TID connections to the next hop
 *
 * @param entry
 * @return port, or -1 if entry is null
 */
int trp_route_get_next_hop_port(TRP_ROUTE *entry)
{
  if (entry)
    return entry->next_hop_port;

  return -1;
}
