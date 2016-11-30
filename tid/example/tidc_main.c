/*
 * Copyright (c) 2012, JANET(UK)
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

#include <gsscon.h>
#include <tr_debug.h>
#include <tid_internal.h>
#include <trust_router/tr_dh.h>

static void tidc_resp_handler (TIDC_INSTANCE * tidc, 
			TID_REQ *req,
			TID_RESP *resp, 
			void *cookie) 
{
  int c_keylen = 0;
  unsigned char *c_keybuf = NULL;
  int i;

  printf ("Response received! Realm = %s, Community = %s.\n", resp->realm->buf, resp->comm->buf);

  /* Generate the client key -- TBD, handle more than one server */
  if (TID_SUCCESS != resp->result) {
    fprintf(stderr, "tidc_resp_handler: Response is an error.\n");
    return;
  }

  if (!resp->servers) {
    fprintf(stderr, "tidc_resp_handler: Response does not contain server info.\n");
    return;
  }
  
  if (0 > (c_keylen = tr_compute_dh_key(&c_keybuf, 
				      resp->servers->aaa_server_dh->pub_key, 
				      req->tidc_dh))) {
    
    printf("tidc_resp_handler: Error computing client key.\n");
    return;
  }
  
  /* Print out the client key. */
  printf("Client Key Generated (len = %d):\n", c_keylen);
  for (i = 0; i < c_keylen; i++) {
    printf("%.2x", c_keybuf[i]); 
  }
  printf("\n");

  return;
}


/* command-line option setup */

/* argp global parameters */
const char *argp_program_bug_address=PACKAGE_BUGREPORT; /* bug reporting address */

/* doc strings */
static const char doc[]=PACKAGE_NAME " - TID Client";
static const char arg_doc[]="<server> <RP-realm> <target-realm> <community> [<port>]"; /* string describing arguments, if any */

/* define the options here. Fields are:
 * { long-name, short-name, variable name, options, help description } */
static const struct argp_option cmdline_options[] = {
  { NULL }
};

/* structure for communicating with option parser */
struct cmdline_args {
  char *server;
  char *rp_realm;
  char *target_realm;
  char *community;
  int port; /* optional */
};

/* parser for individual options - fills in a struct cmdline_args */
static error_t parse_option(int key, char *arg, struct argp_state *state)
{
  /* get a shorthand to the command line argument structure, part of state */
  struct cmdline_args *arguments=state->input;

  switch (key) {
  case ARGP_KEY_ARG: /* handle argument (not option) */
    switch (state->arg_num) {
    case 0:
      arguments->server=arg;
      break;

    case 1:
      arguments->rp_realm=arg;
      break;

    case 2:
      arguments->target_realm=arg;
      break;

    case 3:
      arguments->community=arg;
      break;

    case 4:
      arguments->port=strtol(arg, NULL, 10); /* optional */
      break;

    default:
      /* too many arguments */
      argp_usage(state);
    }
    break;

  case ARGP_KEY_END: /* no more arguments */
    if (state->arg_num < 4) {
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

int main (int argc, 
          char *argv[]) 
{
  TIDC_INSTANCE *tidc;
  int conn = 0;
  int rc;
  gss_ctx_id_t gssctx;
  struct cmdline_args opts;

  /* parse the command line*/
  /* set defaults */
  opts.server=NULL;
  opts.rp_realm=NULL;
  opts.target_realm=NULL;
  opts.community=NULL;
  opts.port=TID_PORT;

  argp_parse(&argp, argc, argv, 0, 0, &opts);
  /* TBD -- validity checking, dealing with quotes, etc. */

  /* Use standalone logging */
  tr_log_open();

  /* set logging levels */
  talloc_set_log_stderr();
  tr_log_threshold(LOG_CRIT);
  tr_console_threshold(LOG_DEBUG);

  printf("TIDC Client:\nServer = %s, rp_realm = %s, target_realm = %s, community = %s, port = %i\n", opts.server, opts.rp_realm, opts.target_realm, opts.community, opts.port);
 
  /* Create a TID client instance & the client DH */
  tidc = tidc_create();
  if (NULL == (tidc->client_dh = tr_create_dh_params(NULL, 0))) {
    printf("Error creating client DH params.\n");
    return 1;
  }

  /* Set-up TID connection */
  if (-1 == (conn = tidc_open_connection(tidc, opts.server, opts.port, &gssctx))) {
    /* Handle error */
    printf("Error in tidc_open_connection.\n");
    return 1;
  };

  /* Send a TID request */
  if (0 > (rc = tidc_send_request(tidc, conn, gssctx, opts.rp_realm, opts.target_realm, opts.community, 
				  &tidc_resp_handler, NULL))) {
    /* Handle error */
    printf("Error in tidc_send_request, rc = %d.\n", rc);
    return 1;
  }
    
  /* Clean-up the TID client instance, and exit */
  tidc_free(tidc);

  return 0;
}

