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

#include <stdio.h>
#include <talloc.h>
#include <assert.h>

#include <tr_gss_names.h>
#include <trp_route.h>
#include <trp_internal.h>
#include <trp_ptable.h>


/* Can't do the updates test because trps_select_updates_for_peer() is now static */
#define VERIFY_UPDATES 0

struct peer_entry {
  char *server;
  char *gss_name;
  unsigned int port;
  unsigned int linkcost;
};

static struct peer_entry peer_data[]={
  {"peer0", "trustrouter@peer0", 10000, 0x0001},
  {"peer1", "trustrouter@peer1", 15000, 0x0002},
  {"peer2", "trustrouter@peer2", 20000, 0x0004},
  {"peer3", "trustrouter@peer3", 25000, 0x0008},
  {"peer4", "trustrouter@peer4", 30000, 0x0010}
};
static size_t n_peers=sizeof(peer_data)/sizeof(peer_data[0]);

static void populate_ptable(TRPS_INSTANCE *trps)
{
  TRP_PEER *new_peer;
  int i;

  for (i=0; i<n_peers; i++) {
    new_peer=trp_peer_new(NULL);
    assert(new_peer!=NULL);
    trp_peer_set_server(new_peer, peer_data[i].server);
    assert(trp_peer_get_server(new_peer)!=NULL);
    trp_peer_add_gss_name(new_peer, tr_new_name(peer_data[i].gss_name));
    assert(trp_peer_get_gss_names(new_peer)!=NULL);
    trp_peer_set_port(new_peer, peer_data[i].port);
    trp_peer_set_linkcost(new_peer, peer_data[i].linkcost);
    assert(trps_add_peer(trps, new_peer)==TRP_SUCCESS);
  }
}

static struct peer_entry *find_peer_entry(char *server)
{
  int i;
  for (i=0; i<n_peers; i++) {
    if (0==strcmp(server, peer_data[i].server)) {
      return (peer_data+i);
    }
  }
  return NULL;
}

static void verify_ptable(TRPS_INSTANCE *trps)
{
  struct peer_entry *peer_entry=NULL;
  TRP_PEER *peer;
  char *s;
  TR_NAME *gssname;

  peer=trps->ptable->head;
  while (peer!=NULL) {
    peer_entry=find_peer_entry(trp_peer_get_server(peer));
    assert(peer_entry!=NULL);
    assert(!strcmp(trp_peer_get_server(peer), peer_entry->server));
    assert(trp_peer_get_port(peer)==peer_entry->port);
    assert(trp_peer_get_linkcost(peer)==peer_entry->linkcost);
    assert(0<asprintf(&s, "trustrouter@%s", peer_entry->server));
    gssname=tr_new_name(s);
    free(s);
    assert(gssname!=NULL);
    assert(tr_gss_names_matches(trp_peer_get_gss_names(peer), gssname));
    tr_free_name(gssname);
    peer=peer->next;
  }
}

struct route_data {
  char *apc;
  char *realm;
  char *peer;
  unsigned int metric;
  char *trust_router;
  char *next_hop;
  int selected;
  unsigned int interval;
  int verified; /* for testing */
};
static struct route_data route_table[]={
  {"apc0", "realm0", "", 0, "tr.r0.apc0", "", 1, 60, 0},
  {"apc0", "realm1", "", 0, "tr.r1.apc0", "", 1, 60, 0},
  {"apc0", "realm0", "trustrouter@peer0", 1, "tr.r0.apc0", "trustrouter@peer0", 0, 60, 0},
  {"apc0", "realm1", "trustrouter@peer0", 0, "tr.r1.apc0", "trustrouter@peer0", 0, 60, 0},
  {"apc0", "realm2", "trustrouter@peer0", 0, "tr.r2.apc0", "trustrouter@peer0", 1, 60, 0},
  {"apc0", "realm3", "trustrouter@peer0", 1, "tr.r3.apc0", "trustrouter@peer0", 0, 60, 0},
  {"apc0", "realm4", "trustrouter@peer0", 2, "tr.r4.apc0", "trustrouter@peer0", 0, 60, 0},
  {"apc0", "realm0", "trustrouter@peer1", 0, "tr.r0.apc0", "trustrouter@peer1", 0, 60, 0},
  {"apc0", "realm1", "trustrouter@peer1", 1, "tr.r1.apc0", "trustrouter@peer1", 0, 60, 0},
  {"apc0", "realm2", "trustrouter@peer1", 1, "tr.r2.apc0", "trustrouter@peer1", 0, 60, 0},
  {"apc0", "realm3", "trustrouter@peer1", 0, "tr.r3.apc0", "trustrouter@peer1", 1, 60, 0},
  {"apc0", "realm4", "trustrouter@peer1", 2, "tr.r4.apc0", "trustrouter@peer1", 0, 60, 0},
  {"apc0", "realm0", "trustrouter@peer2", 0, "tr.r0.apc0", "trustrouter@peer2", 0, 60, 0},
  {"apc0", "realm1", "trustrouter@peer2", 2, "tr.r1.apc0", "trustrouter@peer2", 0, 60, 0},
  {"apc0", "realm2", "trustrouter@peer2", 2, "tr.r2.apc0", "trustrouter@peer2", 0, 60, 0},
  {"apc0", "realm3", "trustrouter@peer2", 1, "tr.r3.apc0", "trustrouter@peer2", 0, 60, 0},
  {"apc0", "realm4", "trustrouter@peer2", 0, "tr.r4.apc0", "trustrouter@peer2", 1, 60, 0},
};
static size_t n_routes=sizeof(route_table)/sizeof(route_table[0]);

#if VERIFY_UPDATES
/* These are the correct updates to select from the above route table for each peer.
 * The rule is: send selected route unless it is through that peer, otherwise send
 * the best (lowest metric) alternative route. 
 *
 * In a few cases there are multiple valid options (when a two non-selected routes
 * exist). If these tests are failing, it may be that the trps code is selecting another
 * valid option, so check that. Probably ought to tweak metrics to avoid that ambiguity. */
static struct route_data update_table[][10]={
  { /* peer0 */
    {"apc0", "realm0", "", 0, "tr.r0.apc0", "", 1, 60, 0},
    {"apc0", "realm1", "", 0, "tr.r1.apc0", "", 1, 60, 0},
    {"apc0", "realm2", "trustrouter@peer1", 1, "tr.r2.apc0", "trustrouter@peer1", 0, 60, 0},
    {"apc0", "realm3", "trustrouter@peer1", 0, "tr.r3.apc0", "trustrouter@peer1", 1, 60, 0},
    {"apc0", "realm4", "trustrouter@peer2", 0, "tr.r4.apc0", "trustrouter@peer2", 1, 60, 0},
    {NULL}
  },
  { /* peer1 */
    {"apc0", "realm0", "", 0, "tr.r0.apc0", "", 1, 60, 0},
    {"apc0", "realm1", "", 0, "tr.r1.apc0", "", 1, 60, 0},
    {"apc0", "realm2", "trustrouter@peer0", 0, "tr.r2.apc0", "trustrouter@peer0", 1, 60, 0},
    {"apc0", "realm3", "trustrouter@peer2", 1, "tr.r3.apc0", "trustrouter@peer2", 0, 60, 0},
    {"apc0", "realm4", "trustrouter@peer2", 0, "tr.r4.apc0", "trustrouter@peer2", 1, 60, 0},
    {NULL}
  },
  { /* peer2 */
    {"apc0", "realm0", "", 0, "tr.r0.apc0", "", 1, 60, 0},
    {"apc0", "realm1", "", 0, "tr.r1.apc0", "", 1, 60, 0},
    {"apc0", "realm2", "trustrouter@peer0", 0, "tr.r2.apc0", "trustrouter@peer0", 1, 60, 0},
    {"apc0", "realm3", "trustrouter@peer1", 0, "tr.r3.apc0", "trustrouter@peer1", 1, 60, 0},
    {"apc0", "realm4", "trustrouter@peer1", 2, "tr.r4.apc0", "trustrouter@peer1", 0, 60, 0},
    {NULL}
  },
  { /* peer3 */
    {"apc0", "realm0", "", 0, "tr.r0.apc0", "", 1, 60, 0},
    {"apc0", "realm1", "", 0, "tr.r1.apc0", "", 1, 60, 0},
    {"apc0", "realm2", "trustrouter@peer0", 0, "tr.r2.apc0", "trustrouter@peer0", 1, 60, 0},
    {"apc0", "realm3", "trustrouter@peer1", 0, "tr.r3.apc0", "trustrouter@peer1", 1, 60, 0},
    {"apc0", "realm4", "trustrouter@peer2", 0, "tr.r4.apc0", "trustrouter@peer2", 1, 60, 0},
    {NULL}
  },
  { /* peer4 */
    {"apc0", "realm0", "", 0, "tr.r0.apc0", "", 1, 60, 0},
    {"apc0", "realm1", "", 0, "tr.r1.apc0", "", 1, 60, 0},
    {"apc0", "realm2", "trustrouter@peer0", 0, "tr.r2.apc0", "trustrouter@peer0", 1, 60, 0},
    {"apc0", "realm3", "trustrouter@peer1", 0, "tr.r3.apc0", "trustrouter@peer1", 1, 60, 0},
    {"apc0", "realm4", "trustrouter@peer2", 0, "tr.r4.apc0", "trustrouter@peer2", 1, 60, 0},
    {NULL}
  }
};
#endif /* VERIFY_UPDATES */

static void populate_rtable(TRPS_INSTANCE *trps)
{
  int i;
  TRP_ROUTE *new;

  for (i=0; i<n_routes; i++) {
    new=trp_route_new(NULL);
    assert(new!=NULL);
    trp_route_set_comm(new, tr_new_name(route_table[i].apc));
    trp_route_set_realm(new, tr_new_name(route_table[i].realm));
    trp_route_set_peer(new, tr_new_name(route_table[i].peer));
    trp_route_set_metric(new, route_table[i].metric);
    trp_route_set_trust_router(new, tr_new_name(route_table[i].trust_router));
    trp_route_set_next_hop(new, tr_new_name(route_table[i].next_hop));
    trp_route_set_selected(new, route_table[i].selected);
    trp_route_set_interval(new, route_table[i].interval);
    /* do not set expiry */
    trp_rtable_add(trps->rtable, new);
    new=NULL;
  }
}

#if VERIFY_UPDATES
static void verify_update(TRP_ROUTE **updates, size_t n_updates, struct route_data *expected)
{
  int ii,jj;
  int found;

  for(jj=0; jj<n_updates; jj++) {
    found=0;
    for (ii=0; expected[ii].apc!=NULL; ii++) {
      if ((0==strcmp(expected[ii].apc, updates[jj]->comm->buf))
         &&(0==strcmp(expected[ii].realm, updates[jj]->realm->buf))
         &&(0==strcmp(expected[ii].peer, updates[jj]->peer->buf))
         &&(expected[ii].metric==updates[jj]->metric)
         &&(0==strcmp(expected[ii].trust_router, updates[jj]->trust_router->buf))
         &&(0==strcmp(expected[ii].next_hop, updates[jj]->next_hop->buf))
         &&(expected[ii].selected==updates[jj]->selected)
         &&(expected[ii].interval==updates[jj]->interval)) {
        assert(expected[ii].verified==0); /* should only encounter each entry once */
        expected[ii].verified=1;
        found=1;
        continue;
      }
    }
    if (!found) {
      printf("missing:\n%s\n", trp_route_to_str(NULL,updates[jj], " | "));
      assert(0);
    }
  }
  for(ii=0; expected[ii].apc!=NULL; ii++)
    assert(expected[ii].verified==1);
}

static void verify_update_selection(TRPS_INSTANCE *trps)
{
  int ii;
  TRP_ROUTE **updates=NULL;
  size_t n_updates;
  TR_NAME *gssname=NULL;
  char *s;

  for (ii=0; ii<n_peers; ii++) {
    assert(0<asprintf(&s, "trustrouter@%s", peer_data[ii].server));
    assert(NULL!=(gssname=tr_new_name(s)));
    free(s);

    updates=trps_select_updates_for_peer(NULL, trps, gssname, &n_updates);
    tr_free_name(gssname);
    verify_update(updates, n_updates, update_table[ii]);
    talloc_free(updates);
  }
}
#endif /* VERIFY_UPDATES */

int main(void)
{
  TALLOC_CTX *main_ctx=talloc_new(NULL);
  TRPS_INSTANCE *trps;
  char *s;

  trps=trps_new(main_ctx);

  printf("\nPopulating peer table...\n");
  populate_ptable(trps);

  printf("\nVerifying peer table...\n");
  verify_ptable(trps);

  printf("\nPopulating route table...\n");
  populate_rtable(trps);
  s=trp_rtable_to_str(main_ctx, trps->rtable, " | ", NULL);
  printf("Route Table:\n%s---\n", s);

#if VERIFY_UPDATES
  printf("\nVerifying route update selection...\n");
  verify_update_selection(trps);
#endif /* VERIFY_UPDATES */

  printf("\nDone\n\n");
  talloc_report_full(main_ctx, stderr);
  talloc_free(main_ctx);
  talloc_report_full(NULL, stderr);
  return 0;
}
