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
#include <string.h>

#include <trust_router/tid.h>
#include <tr_dh.h>

static int tids_req_handler (TIDS_INSTANCE * tids,
		      TID_REQ *req, 
		      TID_RESP **resp,
		      void *cookie)
{
  unsigned char *s_keybuf = NULL;
  int s_keylen = 0;
  int i = 0;

  printf("Request received! target_realm = %s, community = %s\n", req->realm->buf, req->comm->buf);
  if (tids)
    tids->req_count++;

  if (!(resp) || !(*resp)) {
    printf("tids_req_handler: No response structure.\n");
    return -1;
  }

  /* Allocate a new server block */
  if (NULL == ((*resp)->servers = malloc(sizeof(TID_SRVR_BLK)))){
    printf("tids_req_handler(): malloc failed.\n");
    return -1;
  }
  memset((*resp)->servers, 0, sizeof(TID_SRVR_BLK));

  /* TBD -- Set up the server IP Address */

  if (!(req) || !(req->tidc_dh)) {
    printf("tids_req_handler(): No client DH info.\n");
    return -1;
  }

  if ((!req->tidc_dh->p) || (!req->tidc_dh->g)) {
    printf("tids_req_handler(): NULL dh values.\n");
    return -1;
  }

  /* Generate the server DH block based on the client DH block */
  printf("Generating the server DH block.\n");
  printf("...from client DH block, dh_g = %s, dh_p = %s.\n", BN_bn2hex(req->tidc_dh->g), BN_bn2hex(req->tidc_dh->p));

  if (NULL == ((*resp)->servers->aaa_server_dh = tr_create_matching_dh(NULL, 0, req->tidc_dh))) {
    printf("tids_req_handler(): Can't create server DH params.\n");
    return -1;
  }

  /* Generate the server key */
  printf("Generating the server key.\n");
  if (NULL == (s_keybuf = malloc(DH_size((*resp)->servers->aaa_server_dh)))) {
    printf ("tids_req_handler(): Can't allocate server keybuf.\n");
    return -1;
  }

  if (0 > (s_keylen = tr_compute_dh_key(s_keybuf, 
					DH_size((*resp)->servers->aaa_server_dh), 
					req->tidc_dh->pub_key, 
				        (*resp)->servers->aaa_server_dh))) {
    printf("tids_req_handler(): Key computation failed.");
    return -1;
  }

  /* Print out the key.  If this were a AAA server, we'd store the key. */
  printf("tids_req_handler(): Server Key Generated (len = %d):\n", s_keylen);
  for (i = 0; i < s_keylen; i++) {
    printf("%x", s_keybuf[i]); 
  }
  printf("\n");
  return s_keylen;
}

int main (int argc, 
	  const char *argv[]) 
{
  static TIDS_INSTANCE *tids;
  int rc = 0;

  /* Parse command-line arguments */ 
  if (argc != 1)
    printf("Unexpected arguments, ignored.\n");

  /* Create a TID server instance */
  if (NULL == (tids = tids_create())) {
    printf("Error in tids_create().  Exiting.\n");
    return 1;
  }

  /* Start-up the server, won't return unless there is an error. */
  rc = tids_start(tids, &tids_req_handler , NULL);
  
  printf("Error in tids_start(), rc = %d. Exiting.\n", rc);

  /* Clean-up the TID server instance */
  tids_destroy(tids);

  return 1;
}

