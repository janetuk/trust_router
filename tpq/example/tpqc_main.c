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

#include <stdio.h>

#include <tpq.h>

static int tpqc_response_received = 0;

void tpqc_print_usage (const char *name)
{
  printf("Usage: %s <server> <realm> <coi>\n", name);
}

void tpqc_resp_handler (TPQC_INSTANCE * tpqc, 
			TPQ_RESP *resp, 
			void *cookie) 
{
  printf ("Response received! Realm = %s, COI = %s.\n", resp->realm->buf, 
	  resp->coi->buf);
  tpqc_response_received = 1;
}

int main (int argc, 
	  const char *argv[]) 
{
  TPQC_INSTANCE *tpqc;
  TPQ_REQ *treq;
  char *server = NULL;
  char *realm = NULL;
  char *coi = NULL;
  void *cookie = NULL;
  int conn = 0;
  int rc;

  /* Parse command-line arguments */ 
  if (argc != 4)
    tpqc_print_usage(argv[0]);

  /* TBD -- validity checking, dealing with quotes, etc. */
  server = (char *)argv[1];
  realm = (char *)argv[2];
  coi = (char *)argv[3];

  /* Create a TPQ client instance */
  tpqc = tpqc_create();

  /* Set-up TPQ connection */
  if (-1 == (conn = tpqc_open_connection(tpqc, server))) {
    /* Handle error */
    printf("Error in tpqc_open_connection.\n");
    return 1;
  };

  /* Send a TPQ request */
  if (rc = tpqc_send_request(tpqc, conn, realm, coi, &tpqc_resp_handler, NULL)) {
    /* Handle error */
    printf("Error in tpqc_send_request, rc = &d.\n", rc);
    return 1;
  }
    
  /* Wait for a response */
  while (!tpqc_response_received);

  /* Clean-up the TPQ client instance, and exit */
  tpqc_destroy(tpqc);

  return 0;
}

