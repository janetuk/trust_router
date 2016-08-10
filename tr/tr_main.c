/*
 * Copyright (c) 2012, 2015, JANET(UK)
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
#include <stdlib.h>
#include <jansson.h>
#include <argp.h>
#include <event2/event.h>
#include <talloc.h>
#include <sys/time.h>
#include <signal.h>
#include <pthread.h>

#include <tid_internal.h>
#include <tr_tid.h>
#include <tr_trp.h>
#include <tr_config.h>
#include <tr_event.h>
#include <tr_cfgwatch.h>
#include <tr.h>
#include <tr_debug.h>

#define TALLOC_DEBUG_ENABLE 1
#define DEBUG_HARDCODED_PEER_TABLE 1
#define DEBUG_PING_SELF 0

/***** command-line option handling / setup *****/

/* Strip trailing / from a path name.*/
static void remove_trailing_slash(char *s) {
  size_t n;

  n=strlen(s);
  if(s[n-1]=='/') {
    s[n-1]='\0';
  }
}

/* argp global parameters */
const char *argp_program_bug_address=PACKAGE_BUGREPORT; /* bug reporting address */

/* doc strings */
static const char doc[]=PACKAGE_NAME " - Moonshot Trust Router";
static const char arg_doc[]=""; /* string describing arguments, if any */

/* define the options here. Fields are:
 * { long-name, short-name, variable name, options, help description } */
static const struct argp_option cmdline_options[] = {
    { "config-dir", 'c', "DIR", 0, "Specify configuration file location (default is current directory)"},
    { NULL }
};

/* structure for communicating with option parser */
struct cmdline_args {
  char *config_dir;
};

/* parser for individual options - fills in a struct cmdline_args */
static error_t parse_option(int key, char *arg, struct argp_state *state)
{
  /* get a shorthand to the command line argument structure, part of state */
  struct cmdline_args *arguments=state->input;

  switch (key) {
  case 'c':
    if (arg == NULL) {
      /* somehow we got called without an argument */
      return ARGP_ERR_UNKNOWN;
    }
    arguments->config_dir=arg;
    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }

  return 0; /* success */
}

/* assemble the argp parser */
static struct argp argp = {cmdline_options, parse_option, arg_doc, doc};


/***** talloc error handling *****/
/* called when talloc tries to abort */
static void tr_abort(const char *reason)
{
  tr_crit("tr_abort: Critical error, talloc aborted. Reason: %s", reason);
  abort();
}

#if TALLOC_DEBUG_ENABLE
static void tr_talloc_log(const char *msg)
{
  tr_debug("talloc: %s", msg);
}
#endif /* TALLOC_DEBUG_ENABLE */


#if DEBUG_PING_SELF
struct thingy {
  TRPS_INSTANCE *trps;
  struct event *ev;
};

static void debug_ping(evutil_socket_t fd, short what, void *arg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct thingy *thingy=(struct thingy *)arg;
  TRPS_INSTANCE *trps=thingy->trps;
  TRP_REQ *req=NULL;
  TR_MSG msg;
  char *encoded=NULL;
  struct timeval interval={1, 0};
  static int count=10;
  TR_NAME *name=NULL;

  tr_debug("debug_ping entered");
  if (trps->trpc==NULL)
    tr_trpc_initiate(trps, trps->hostname, trps->port);

  /* create a TRP route request msg */
  req=trp_req_new(tmp_ctx);
  name=tr_new_name("community");
  trp_req_set_comm(req, name);
  name=tr_new_name("realm");
  trp_req_set_realm(req, name);
  tr_msg_set_trp_req(&msg, req);
  encoded=tr_msg_encode(&msg);
  if (encoded==NULL)
    tr_err("debug_ping: error encoding TRP message.");
  else {
    tr_debug("debug_ping: sending message");
    trps_send_msg(trps, NULL, encoded);
    tr_msg_free_encoded(encoded);
  }
  if (count-- > 0)
    evtimer_add(thingy->ev, &interval);
}
#endif /* DEBUG_PING_SELF */

static void configure_signals(void)
{
  sigset_t signals;
  /* ignore SIGPIPE */
  sigemptyset(&signals);
  sigaddset(&signals, SIGPIPE);
  pthread_sigmask(SIG_BLOCK, &signals, NULL);
}

int main(int argc, char *argv[])
{
  TALLOC_CTX *main_ctx=NULL;

  TR_INSTANCE *tr = NULL;
  struct cmdline_args opts;
  struct event_base *ev_base;
  struct tr_socket_event tids_ev;
  struct event *cfgwatch_ev;

#if DEBUG_PING_SELF
  struct event *debug_ping_ev;
  struct timeval notime={0, 0};
  struct thingy thingy={NULL};
#endif /* DEBUG_PING_SELF */

  configure_signals();

  /* we're going to be multithreaded, so disable null context tracking */
  talloc_set_abort_fn(tr_abort);
  talloc_disable_null_tracking();
#if TALLOC_DEBUG_ENABLE
  talloc_set_log_fn(tr_talloc_log);
#endif /* TALLOC_DEBUG_ENABLE */
  main_ctx=talloc_new(NULL);

  /* Use standalone logging */
  tr_log_open();

  /***** parse command-line arguments *****/
  /* set defaults */
  opts.config_dir=".";

  /* parse the command line*/
  argp_parse(&argp, argc, argv, 0, 0, &opts);

  /* process options */
  remove_trailing_slash(opts.config_dir);

  /***** create a Trust Router instance *****/
  if (NULL == (tr = tr_create(main_ctx))) {
    tr_crit("Unable to create Trust Router instance, exiting.");
    return 1;
  }

  /***** initialize the trust path query server instance *****/
  if (NULL == (tr->tids = tids_create (tr))) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    return 1;
  }

  /***** initialize the trust router protocol server instance *****/
  if (NULL == (tr->trps = trps_new(tr))) {
    tr_crit("Error initializing Trust Router Protocol Server instance.");
    return 1;
  }

  /***** process configuration *****/
  tr->cfgwatch=tr_cfgwatch_create(tr);
  if (tr->cfgwatch == NULL) {
    tr_crit("Unable to create configuration watcher object, exiting.");
    return 1;
  }
  tr->cfgwatch->config_dir=opts.config_dir;
  tr->cfgwatch->cfg_mgr=tr->cfg_mgr;
  tr->cfgwatch->update_cb=tr_config_changed; /* handle configuration changes */
  tr->cfgwatch->update_cookie=(void *)tr;
  if (0 != tr_read_and_apply_config(tr->cfgwatch)) {
    tr_crit("Error reading configuration, exiting.");
    return 1;
  }

  /***** Set up the event loop *****/
  ev_base=tr_event_loop_init(); /* Set up the event loop */
  if (ev_base==NULL) {
    tr_crit("Error initializing event loop.");
    return 1;
  }

  /* already set config_dir, fstat_list and n_files earlier */
  if (0 != tr_cfgwatch_event_init(ev_base, tr->cfgwatch, &cfgwatch_ev)) {
    tr_crit("Error initializing configuration file watcher.");
    return 1;
  }

  /*tr_status_event_init();*/ /* install status reporting events */

  /* install TID server events */
  if (0 != tr_tids_event_init(ev_base,
                              tr->tids,
                              tr->cfg_mgr,
                             &tids_ev)) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    return 1;
  }

  /* install TRP handler events */
  if (TRP_SUCCESS != tr_trps_event_init(ev_base, tr)) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    return 1;
  }

#if DEBUG_HARDCODED_PEER_TABLE
  {
    TRP_PEER *hc_peer=NULL;
    char *s=NULL;

    hc_peer=trp_peer_new(main_ctx); /* will later be stolen by ptable context */
    if (hc_peer==NULL) {
      tr_crit("Unable to allocate new peer. Aborting.");
      return 1;
    }
    trp_peer_set_server(hc_peer, "epsilon.vmnet");
    trp_peer_set_gssname(hc_peer, tr_new_name("tr-epsilon-vmnet@apc.painless-security.com"));
    trp_peer_set_conn_status_cb(hc_peer, tr_peer_status_change, (void *)(tr->trps));
    switch (tr->trps->port) {
    case 10000:
      trp_peer_set_port(hc_peer, 10001);
      break;
    case 10001:
      trp_peer_set_port(hc_peer, 10000);
      break;
    default:
      tr_crit("Cannot use hardcoded peer table with port other than 10000 or 10001.");
      return 1;
    }
    if (TRP_SUCCESS != trps_add_peer(tr->trps, hc_peer)) {
      tr_crit("Unable to add peer.");
      return 1;
    }

    hc_peer=trp_peer_new(main_ctx); /* will later be stolen by ptable context */
    if (hc_peer==NULL) {
      tr_crit("Unable to allocate new peer. Aborting.");
      return 1;
    }
    trp_peer_set_server(hc_peer, "epsilon-trpc.vmnet");
    trp_peer_set_gssname(hc_peer, tr_new_name("trpc@apc.painless-security.com"));
    trp_peer_set_port(hc_peer, 10002); /* not really used */
    if (TRP_SUCCESS != trps_add_peer(tr->trps, hc_peer)) {
      tr_crit("Unable to add peer.");
      return 1;
    }
    
    s=trp_ptable_to_str(main_ctx, tr->trps->ptable, NULL, NULL);
    tr_debug("Peer Table:\n%s\n", s);
    talloc_free(s);
  }
#endif /* DEBUG_HARDCODED_PEER_TABLE */

#if DEBUG_PING_SELF
  /* for debugging, send a message to peers on a timer */
  debug_ping_ev=evtimer_new(ev_base, debug_ping, (void *)&thingy);
  thingy.trps=tr->trps;
  thingy.ev=debug_ping_ev;
  evtimer_add(debug_ping_ev, &notime);
#endif /* DEBUG_PING_SELF */

  tr_event_loop_run(ev_base); /* does not return until we are done */

  /* TODO: ensure talloc is properly used so this actually works */
  tr_destroy(tr); /* thanks to talloc, should destroy everything */

  talloc_free(main_ctx);
  return 0;
}
