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
#include <stdlib.h>
#include <sqlite3.h>

#include <tr_debug.h>
#include <trust_router/tid.h>
#include <trust_router/tr_dh.h>
#include <openssl/rand.h>

static sqlite3 *db = NULL;
static sqlite3_stmt *insert_stmt = NULL;

static int  create_key_id(char *out_id, size_t len)
{
  unsigned char rand_buf[32];
  size_t bin_len;
  if (len <8)
    return -1;
  strncpy(out_id, "key-", len);
  len -= 4;
  out_id += 4;
  if (sizeof(rand_buf)*2+1 < len)
    len = sizeof(rand_buf)*2 + 1;
  bin_len = (len-1)/2;
  if (-1 == RAND_pseudo_bytes(rand_buf, bin_len))
      return -1;
  tr_bin_to_hex(rand_buf, bin_len, out_id, len);
  out_id[bin_len*2] = '\0';
  return 0;
}
  
static int tids_req_handler (TIDS_INSTANCE *tids,
		      TID_REQ *req, 
		      TID_RESP **resp,
		      void *cookie)
{
  unsigned char *s_keybuf = NULL;
  int s_keylen = 0;
  char key_id[12];
  unsigned char *pub_digest;
  size_t pub_digest_len;
  

  fprintf(stdout, "tids_req_handler: Request received! target_realm = %s, community = %s\n", req->realm->buf, req->comm->buf);
  if (tids)
    tids->req_count++;

  if (!(resp) || !(*resp)) {
    fprintf(stderr, "tids_req_handler: No response structure.\n");
    return -1;
  }

  /* Allocate a new server block */
  if (NULL == ((*resp)->servers = malloc(sizeof(TID_SRVR_BLK)))){
    fprintf(stderr, "tids_req_handler(): malloc failed.\n");
    return -1;
  }
  memset((*resp)->servers, 0, sizeof(TID_SRVR_BLK));

  /* TBD -- Set up the server IP Address */

  if (!(req) || !(req->tidc_dh)) {
    fprintf(stderr, "tids_req_handler(): No client DH info.\n");
    return -1;
  }

  if ((!req->tidc_dh->p) || (!req->tidc_dh->g)) {
    fprintf(stderr, "tids_req_handler(): NULL dh values.\n");
    return -1;
  }

  /* Generate the server DH block based on the client DH block */
  // fprintf(stderr, "Generating the server DH block.\n");
  // fprintf(stderr, "...from client DH block, dh_g = %s, dh_p = %s.\n", BN_bn2hex(req->tidc_dh->g), BN_bn2hex(req->tidc_dh->p));

  if (NULL == ((*resp)->servers->aaa_server_dh = tr_create_matching_dh(NULL, 0, req->tidc_dh))) {
    fprintf(stderr, "tids_req_handler(): Can't create server DH params.\n");
    return -1;
  }

  if (0 == inet_aton(tids->ipaddr, &((*resp)->servers->aaa_server_addr))) {
    fprintf(stderr, "tids_req_handler(): inet_aton() failed.\n");
    return -1;
  }

  /* Set the key name */
  if (-1 == create_key_id(key_id, sizeof(key_id)))
    return -1;
  (*resp)->servers->key_name = tr_new_name(key_id);

  /* Generate the server key */
  // fprintf(stderr, "Generating the server key.\n");

  if (0 > (s_keylen = tr_compute_dh_key(&s_keybuf, 
					req->tidc_dh->pub_key, 
				        (*resp)->servers->aaa_server_dh))) {
    fprintf(stderr, "tids_req_handler(): Key computation failed.");
    return -1;
  }
  if (0 != tr_dh_pub_hash(req,
			  &pub_digest, &pub_digest_len)) {
    tr_debug("Unable to digest client public key\n");
    return -1;
  }

  if (NULL != insert_stmt) {
    int sqlite3_result;
    sqlite3_bind_text(insert_stmt, 1, key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(insert_stmt, 2, s_keybuf, s_keylen, SQLITE_TRANSIENT);
    sqlite3_bind_blob(insert_stmt, 3, pub_digest, pub_digest_len, SQLITE_TRANSIENT);
    sqlite3_result = sqlite3_step(insert_stmt);
    if (SQLITE_DONE != sqlite3_result)
      printf("sqlite3: failed to write to database\n");
    sqlite3_reset(insert_stmt);
  }
  
  /* Print out the key. */
  // fprintf(stderr, "tids_req_handler(): Server Key Generated (len = %d):\n", s_keylen);
  // for (i = 0; i < s_keylen; i++) {
  // fprintf(stderr, "%x", s_keybuf[i]); 
  // }
  // fprintf(stderr, "\n");

  return s_keylen;
}
static int auth_handler(gss_name_t gss_name, TR_NAME *client,
			void *expected_client)
{
  TR_NAME *expected_client_trname = (TR_NAME*) expected_client;
  return tr_name_cmp(client, expected_client_trname);
}


int main (int argc, 
	  const char *argv[]) 
{
  TIDS_INSTANCE *tids;
  int rc = 0;
  char *ipaddr = NULL;
  const char *hostname = NULL;
  TR_NAME *gssname = NULL;

  /* Parse command-line arguments */ 
  if (argc != 5) {
    fprintf(stdout, "Usage: %s <ip-address> <gss-name> <hostname> <database-name>\n", argv[0]);
    exit(1);
  }
  ipaddr = (char *)argv[1];
  gssname = tr_new_name((char *) argv[2]);
  hostname = argv[3];
  if (SQLITE_OK != sqlite3_open(argv[4], &db)) {
    fprintf(stdout, "Error opening database %s\n", argv[4]);
    exit(1);
  }
  sqlite3_prepare_v2(db, "insert into psk_keys (keyid, key, client_dh_pub) values(?, ?, ?)",
		     -1, &insert_stmt, NULL);

  /* Create a TID server instance */
  if (NULL == (tids = tids_create())) {
    fprintf(stdout, "Unable to create TIDS instance, exiting.\n");
    return 1;
  }

  tids->ipaddr = ipaddr;

  /* Start-up the server, won't return unless there is an error. */
  rc = tids_start(tids, &tids_req_handler , auth_handler, hostname, TID_PORT, gssname);
  
  fprintf(stdout, "Error in tids_start(), rc = %d. Exiting.\n", rc);

  /* Clean-up the TID server instance */
  tids_destroy(tids);

  return 1;
}

