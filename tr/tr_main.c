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
#include <argp.h>
#include <event2/event.h>
#include <talloc.h>
#include <signal.h>
#include <time.h>

#include <tid_internal.h>
#include <mon_internal.h>
#include <tr_mon.h>
#include <tr_tid.h>
#include <tr_trp.h>
#include <tr_config.h>
#include <tr_event.h>
#include <tr_cfgwatch.h>
#include <tr.h>
#include <tr_debug.h>

#define TALLOC_DEBUG_ENABLE 1

/***** command-line option handling / setup *****/

static void print_version_info(void)
{
  tr_info("Moonshot Trust Router %s\n\n", PACKAGE_VERSION);
}

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
static const char doc[]=PACKAGE_NAME " - Moonshot Trust Router " PACKAGE_VERSION;
static const char arg_doc[]=""; /* string describing arguments, if any */

/* define the options here. Fields are:
 * { long-name, short-name, variable name, options, help description } */
static const struct argp_option cmdline_options[] = {
    { "config-dir", 'c', "DIR", 0, "Specify configuration file location (default is current directory)"},
    { "config-validate", 'C', NULL, 0, "Validate configuration files and exit"},
    { "version", 1, NULL, 0, "Print version information and exit"},
    { NULL }
};

/* structure for communicating with option parser */
struct cmdline_args {
    int version_requested;
    int validate_config_and_exit;
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

    case 1:
      arguments->version_requested=1;
      break;

    case 'C':
      arguments->validate_config_and_exit=1;
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

static void configure_signals(void)
{
  sigset_t signals;
  /* ignore SIGPIPE */
  sigemptyset(&signals);
  sigaddset(&signals, SIGPIPE);
  pthread_sigmask(SIG_BLOCK, &signals, NULL);
}

/* Monitoring handlers */
static MON_RC tr_handle_version(void *cookie, json_t **result_ptr)
{
  *result_ptr = json_string(PACKAGE_VERSION);
  return (*result_ptr == NULL) ? MON_NOMEM : MON_SUCCESS;
}

static MON_RC tr_handle_uptime(void *cookie, json_t **result_ptr)
{
  time_t *start_time = cookie;
  *result_ptr = json_integer(time(NULL) - (*start_time));
  return (*result_ptr == NULL) ? MON_NOMEM : MON_SUCCESS;
}

static MON_RC tr_handle_show_rp_clients(void *cookie, json_t **response_ptr)
{
  TR_CFG_MGR *cfg_mgr = talloc_get_type_abort(cookie, TR_CFG_MGR);

  *response_ptr = tr_rp_clients_to_json(cfg_mgr->active->rp_clients);
  return (*response_ptr == NULL) ? MON_NOMEM : MON_SUCCESS;
}

static MON_RC tr_handle_show_cfg_serial(void *cookie, json_t **response_ptr)
{
  TR_CFG_MGR *cfg_mgr = talloc_get_type_abort(cookie, TR_CFG_MGR);

  *response_ptr = tr_cfg_files_to_json_array(cfg_mgr->active);
  return (*response_ptr == NULL) ? MON_NOMEM : MON_SUCCESS;
}



int main(int argc, char *argv[])
{
  TALLOC_CTX *main_ctx=NULL;

  TR_INSTANCE *tr = NULL;
  struct cmdline_args opts;
  struct event_base *ev_base;
  struct tr_socket_event tids_ev = {0};
  struct event *tids_sweep_ev;
  struct tr_socket_event mon_ev = {0};
  struct event *cfgwatch_ev;

  time_t start_time = time(NULL); /* TODO move this? */

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
  opts.version_requested=0;
  opts.validate_config_and_exit=0;
  opts.config_dir=".";

  /* parse the command line*/
  argp_parse(&argp, argc, argv, 0, 0, &opts);

  /* process options */
  remove_trailing_slash(opts.config_dir);


  /***** Print version info *****/
  print_version_info();
  if (opts.version_requested)
    return 0; /* requested that we print version and exit */

  /***** create a Trust Router instance *****/
  if (NULL == (tr = tr_create(main_ctx))) {
    tr_crit("Unable to create Trust Router instance, exiting.");
    return 1;
  }

  /***** initialize the trust path query server instance *****/
  if (NULL == (tr->tids = tids_new(tr))) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    return 1;
  }

  /***** initialize the trust router protocol server instance *****/
  if (NULL == (tr->trps = trps_new(tr))) {
    tr_crit("Error initializing Trust Router Protocol Server instance.");
    return 1;
  }

  /***** initialize the monitoring interface instance *****/
  if (NULL == (tr->mons = mons_new(tr))) {
    tr_crit("Error initializing monitoring interface instance.");
    return 1;
  }
  /* Monitor our tids/trps instances */
  tr->mons->tids = tr->tids;
  tr->mons->trps = tr->trps;

  /* Register monitoring handlers */
  mons_register_handler(tr->mons, MON_CMD_SHOW, OPT_TYPE_SHOW_VERSION, tr_handle_version, NULL);
  mons_register_handler(tr->mons, MON_CMD_SHOW, OPT_TYPE_SHOW_CONFIG_FILES, tr_handle_show_cfg_serial, tr->cfg_mgr);
  mons_register_handler(tr->mons, MON_CMD_SHOW, OPT_TYPE_SHOW_UPTIME, tr_handle_uptime, &start_time);
  mons_register_handler(tr->mons, MON_CMD_SHOW, OPT_TYPE_SHOW_RP_CLIENTS, tr_handle_show_rp_clients, tr->cfg_mgr);
  tr_tid_register_mons_handlers(tr->tids, tr->mons);
  tr_trp_register_mons_handlers(tr->trps, tr->mons);

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

  /***** Exit here if we are just validating our configuration *****/
  if (opts.validate_config_and_exit) {
    tr_info("Valid configuration found in %s.\n", opts.config_dir);
    return 0;
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

  /* install monitoring interface events */
  tr_debug("Initializing monitoring interface events.");
  if (0 != tr_mons_event_init(ev_base, tr->mons, tr->cfg_mgr, &mon_ev)) {
    tr_crit("Error initializing monitoring interface.");
    return 1;
  }

  /* install TID server events */
  tr_debug("Initializing TID server events.");
  if (0 != tr_tids_event_init(ev_base, tr->tids, tr->cfg_mgr, tr->trps, &tids_ev, &tids_sweep_ev)) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    return 1;
  }

  /* tell the trps which port the tid server listens on */
  tr->trps->tids_port = tr->tids->tids_port;

  /* install TRP handler events */
  tr_debug("Initializing Dynamic Trust Router Protocol events.");
  if (TRP_SUCCESS != tr_trps_event_init(ev_base, tr)) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    return 1;
  }

  tr_debug("Starting event loop.");
  tr_event_loop_run(ev_base); /* does not return until we are done */

  tr_destroy(tr); /* thanks to talloc, should destroy everything */

  talloc_free(main_ctx);
  return 0;
}
