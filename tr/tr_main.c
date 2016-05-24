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

#include <tr.h>
#include <tid_internal.h>
#include <tr_tid.h>
#include <tr_config.h>
#include <tr_event.h>
#include <tr_cfgwatch.h>
#include <tr_debug.h>

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


int main (int argc, char *argv[])
{
  TALLOC_CTX *main_ctx=talloc_new(NULL);

  TR_INSTANCE *tr = NULL;
  struct cmdline_args opts;
  struct event_base *ev_base;
  struct tr_socket_event tids_ev;
  struct event *cfgwatch_ev;
  TR_CFGWATCH *cfgwatch; /* config file watcher status */

  /* Use standalone logging */
  tr_log_open();

  /***** parse command-line arguments *****/
  /* set defaults */
  opts.config_dir=".";

  /* parse the command line*/
  argp_parse(&argp, argc, argv, 0, 0, &opts);

  /* process options */
  remove_trailing_slash(opts.config_dir);

  /* Get a configuration status object */
  cfgwatch=tr_cfgwatch_create(main_ctx);
  if (cfgwatch == NULL) {
    tr_crit("Unable to create configuration watcher object, exiting.");
    return 1;
  }
  
  /***** create a Trust Router instance *****/
  if (NULL == (tr = tr_create())) {
    tr_crit("Unable to create Trust Router instance, exiting.");
    return 1;
  }

  /***** process configuration *****/
  cfgwatch->config_dir=opts.config_dir;
  cfgwatch->ctx=main_ctx;
  cfgwatch->tr=tr;
  if (0 != tr_read_and_apply_config(cfgwatch)) {
    tr_crit("Error reading configuration, exiting.");
    return 1;
  }

  /***** initialize the trust path query server instance *****/
  if (0 == (tr->tids = tids_create ())) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    return 1;
  }

  /***** Set up the event loop *****/
  ev_base=tr_event_loop_init(); /* Set up the event loop */
  if (ev_base==NULL) {
    tr_crit("Error initializing event loop.");
    return 1;
  }

  /* install configuration file watching events */
  cfgwatch->poll_interval=(struct timeval) {1,0}; /* set poll interval in {sec, usec} */
  cfgwatch->settling_time=(struct timeval) {5,0}; /* delay for changes to settle before updating */
  
  /* already set config_dir, fstat_list and n_files earlier */
  if (0 != tr_cfgwatch_event_init(ev_base, cfgwatch, &cfgwatch_ev)) {
    tr_crit("Error initializing configuration file watcher.");
    return 1;
  }

  /*tr_status_event_init();*/ /* install status reporting events */

  /* install TID server events */
  if (0 != tr_tids_event_init(ev_base, tr, &tids_ev)) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    return 1;
  }

  /*tr_trp_event_init();*/ /* install TRP handler events */

  fflush(stdout); fflush(stderr);
  tr_event_loop_run(ev_base); /* does not return until we are done */

  /* TODO: update the cleanup code */
  tids_destroy(tr->tids);
  tr_destroy(tr);

  talloc_free(main_ctx);
  return 0;
}
