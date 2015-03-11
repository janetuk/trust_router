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

#include <gsscon.h>
#include <tr_debug.h>
#include <tid_internal.h>
#include <trust_router/tr_dh.h>

void static tidc_print_usage (const char *name)
{
  printf("Usage: %s <server> <RP-realm> <target-realm> <community> [<port>]\n", name);
}

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

int main (int argc, 
	  const char *argv[]) 
{
  TIDC_INSTANCE *tidc;
  char *server = NULL;
  char *rp_realm = NULL;
  char *realm = NULL;
  char *coi = NULL;
  int port = TID_PORT;
  int conn = 0;
  int rc;
  gss_ctx_id_t gssctx;

  /* Use standalone logging */
  tr_log_open();

  /* set logging levels */
  talloc_set_log_stderr();
  tr_log_threshold(LOG_CRIT);
  tr_console_threshold(LOG_DEBUG);

  /* Parse command-line arguments */ 
  if (argc < 5 || argc > 6) {
    tidc_print_usage(argv[0]);
    exit(1);
  }

  /* TBD -- validity checking, dealing with quotes, etc. */
  server = (char *)argv[1];
  rp_realm = (char *) argv[2];
  realm = (char *)argv[3];
  coi = (char *)argv[4];

  if (argc > 5) {
    port = strtol(argv[5], NULL, 10);
  }

  printf("TIDC Client:\nServer = %s, rp_realm = %s, target_realm = %s, community = %s, port = %i\n", server, rp_realm, realm, coi, port);
 
  /* Create a TID client instance & the client DH */
  tidc = tidc_create();
  if (NULL == (tidc->client_dh = tr_create_dh_params(NULL, 0))) {
    printf("Error creating client DH params.\n");
    return 1;
  }

  /* Set-up TID connection */
  if (-1 == (conn = tidc_open_connection(tidc, server, port, &gssctx))) {
    /* Handle error */
    printf("Error in tidc_open_connection.\n");
    return 1;
  };

  /* Send a TID request */
  if (0 > (rc = tidc_send_request(tidc, conn, gssctx, rp_realm, realm, coi, 
				  &tidc_resp_handler, NULL))) {
    /* Handle error */
    printf("Error in tidc_send_request, rc = %d.\n", rc);
    return 1;
  }
    
  /* Clean-up the TID client instance, and exit */
  tidc_destroy(tidc);

  return 0;
}

