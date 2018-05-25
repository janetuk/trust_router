/*
 * Copyright (c) 2012-2018, JANET(UK)
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
#include <stdio.h>
#include <talloc.h>
#include <argp.h>

#include <mon_internal.h>
#include <tr_debug.h>


/* command-line option setup */
static void print_version_info(void)
{
  printf("Moonshot Trust Router Monitoring Client %s\n\n", PACKAGE_VERSION);
}


/* argp global parameters */
const char *argp_program_bug_address=PACKAGE_BUGREPORT; /* bug reporting address */

/* doc strings */
static const char doc[]=PACKAGE_NAME " - Moonshot Trust Router Monitoring Client";
static const char arg_doc[]="<server> <port> <command> [<option> ...]"; /* string describing arguments, if any */

/* define the options here. Fields are:
 * { long-name, short-name, variable name, options, help description } */
static const struct argp_option cmdline_options[] = {
    { "version", 'v', NULL, 0, "Print version information and exit" },
    {NULL}
};

#define MAX_OPTIONS 20
/* structure for communicating with option parser */
struct cmdline_args {
  char *server;
  int port;
  MON_CMD command;
  MON_OPT_TYPE options[MAX_OPTIONS];
  unsigned int n_options;
};

/* parser for individual options - fills in a struct cmdline_args */
static error_t parse_option(int key, char *arg, struct argp_state *state)
{
  long tmp_l = 0;

  /* get a shorthand to the command line argument structure, part of state */
  struct cmdline_args *arguments=state->input;

  switch (key) {
    case 'v':
      print_version_info();
      exit(0);
      break;

    case ARGP_KEY_ARG: /* handle argument (not option) */
      switch (state->arg_num) {
        case 0:
          arguments->server = arg;
          break;

        case 1:
          tmp_l = strtol(arg, NULL, 10);
          if (errno || (tmp_l < 0) || (tmp_l > 65535)) /* max valid port */
            argp_usage(state);

          arguments->port = (int) tmp_l; /* we already checked the range */
          break;

        case 2:
          arguments->command=mon_cmd_from_string(arg);
          if (arguments->command == MON_CMD_UNKNOWN) {
            printf("\nUnknown command '%s'\n", arg);
            argp_usage(state);
          }
          break;

        default:
          if (arguments->n_options >= MAX_OPTIONS) {
            printf("\nToo many command options given, limit is %d\n", MAX_OPTIONS);
            argp_usage(state);
          }

          arguments->options[arguments->n_options] = mon_opt_type_from_string(arg);
          if (arguments->options[arguments->n_options] == OPT_TYPE_UNKNOWN) {
            printf("\nUnknown command option '%s'\n", arg);
            argp_usage(state);
          }
          arguments->n_options++;
          break;
      }
      break;

    case ARGP_KEY_END: /* no more arguments */
      if (state->arg_num < 3) {
        /* not enough arguments encountered */
        argp_usage(state);
      }
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0; /* success */
}


/* assemble the argp parser */
static struct argp argp = {cmdline_options, parse_option, arg_doc, doc};

int main(int argc, char *argv[])
{
  TALLOC_CTX *main_ctx=talloc_new(NULL);
  MONC_INSTANCE *monc = NULL;
  MON_REQ *req = NULL;
  MON_RESP *resp = NULL;
  unsigned int ii;

  struct cmdline_args opts;
  int retval=1; /* exit with an error status unless this gets set to zero */

  /* parse the command line*/
  /* set defaults */
  opts.server = NULL;
  opts.port = TRP_PORT;
  opts.command = MON_CMD_UNKNOWN;
  opts.n_options = 0;

  argp_parse(&argp, argc, argv, 0, 0, &opts);

  /* Use standalone logging */
  tr_log_open();

  /* set logging levels */
  talloc_set_log_stderr();
  tr_log_threshold(LOG_CRIT);
  tr_console_threshold(LOG_WARNING);

  /* Create a MON client instance */
  monc = monc_new(main_ctx);
  if (monc == NULL) {
    printf("Error allocating client instance.\n");
    goto cleanup;
  }

  /* Set-up MON connection */
  if (0 != monc_open_connection(monc, opts.server, opts.port)) {
    /* Handle error */
    printf("Error opening connection to %s:%d.\n", opts.server, opts.port);
    goto cleanup;
  };

  req = mon_req_new(main_ctx, opts.command);
  for (ii=0; ii < opts.n_options; ii++) {
    if (MON_SUCCESS != mon_req_add_option(req, opts.options[ii])) {
      printf("Error adding option '%s' to request. Request not sent.\n",
             mon_opt_type_to_string(opts.options[ii]));
      goto cleanup;
    }

  }

  /* Send a MON request and get the response */
  resp = monc_send_request(main_ctx, monc, req);

  if (resp == NULL) {
    /* Handle error */
    printf("Error executing monitoring request.\n");
    goto cleanup;
  }

  /* Print the JSON to stdout */
  json_dumpf(mon_resp_encode(resp), stdout, JSON_INDENT(4));
  printf("\n");

  /* success */
  retval = 0;

  /* Clean-up the MON client instance, and exit */
cleanup:
  talloc_free(main_ctx);
  return retval;
}

