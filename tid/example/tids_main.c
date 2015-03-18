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
#include <talloc.h>
#include <sqlite3.h>

#include <tr_debug.h>
#include <tid_internal.h>
#include <trust_router/tr_constraint.h>
#include <trust_router/tr_dh.h>
#include <openssl/rand.h>

static sqlite3 *db = NULL;
static sqlite3_stmt *insert_stmt = NULL;
static sqlite3_stmt *authorization_insert = NULL;

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

static int sqlify_wc(
		     TID_REQ *req,
		     const char **wc,
		     size_t len,
		     char **error)
{
  size_t lc;
  *error = NULL;
  for (lc = 0; lc < len; lc++) {
    if (strchr(wc[lc], '%')) {
      *error = talloc_asprintf( req, "Constraint match `%s' is not appropriate for SQL",
				  wc[lc]);
      return -1;
    }
    if ('*' ==wc[lc][0]) {
      char *s;
      s = talloc_strdup(req, wc[lc]);
      s[0] = '%';
      wc[lc] = s;
    }
  }
  return 0;
}

	

static int handle_authorizations(TID_REQ *req, const unsigned char *dh_hash,
				 size_t hash_len)
{
  TR_CONSTRAINT_SET *intersected = NULL;
  const char **domain_wc, **realm_wc;
  size_t domain_len, realm_len;
  size_t domain_index, realm_index;
  char *error;
  int sqlite3_result;

  if (!req->cons) {
    tr_debug("Request has no constraints, so no authorizations.");
    return 0;
  }
  intersected = tr_constraint_set_intersect(req, req->cons);
  if (!intersected)
    return -1;
  if (0 != tr_constraint_set_get_match_strings(req,
					       intersected, "domain",
					       &domain_wc, &domain_len))
    return -1;
  if (0 != tr_constraint_set_get_match_strings(req,
					       intersected, "realm",
					       &realm_wc, &realm_len))
    return -1;
  tr_debug(" %u domain constraint matches and %u realm constraint matches",
	   (unsigned) domain_len, (unsigned) realm_len);
  if (0 != sqlify_wc(req, domain_wc, domain_len, &error)) {
    tr_debug("Processing domain constraints: %s", error);
    return -1;
  }else if (0 != sqlify_wc(req, realm_wc, realm_len, &error)) {
    tr_debug("Processing realm constraints: %s", error);
    return -1;
  }
  if (!authorization_insert) {
    tr_debug( " No database, no authorizations inserted");
    return 0;
  }
  for (domain_index = 0; domain_index < domain_len; domain_index++)
    for (realm_index = 0; realm_index < realm_len; realm_index++) {
      TR_NAME *community = req->orig_coi;
      if (!community)
	community = req->comm;
      sqlite3_bind_blob(authorization_insert, 1, dh_hash, hash_len, SQLITE_TRANSIENT);
      sqlite3_bind_text(authorization_insert, 2, community->buf, community->len, SQLITE_TRANSIENT);
      sqlite3_bind_text(authorization_insert, 3, realm_wc[realm_index], -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(authorization_insert, 4, domain_wc[domain_index], -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(authorization_insert, 5, req->comm->buf, req->comm->len, SQLITE_TRANSIENT);
      sqlite3_result = sqlite3_step(authorization_insert);
      if (SQLITE_DONE != sqlite3_result)
	tr_crit("sqlite3: failed to write to database");
      sqlite3_reset(authorization_insert);
    }
  return 0;
}


static int tids_req_handler (TIDS_INSTANCE *tids,
		      TID_REQ *req, 
		      TID_RESP *resp,
		      void *cookie)
{
  unsigned char *s_keybuf = NULL;
  int s_keylen = 0;
  char key_id[12];
  unsigned char *pub_digest;
  size_t pub_digest_len;
  

  tr_debug("tids_req_handler: Request received! target_realm = %s, community = %s", req->realm->buf, req->comm->buf);
  if (tids)
    tids->req_count++;

  if (!(resp) || !resp) {
    tr_debug("tids_req_handler: No response structure.");
    return -1;
  }

  /* Allocate a new server block */
  if (NULL == (resp->servers = malloc(sizeof(TID_SRVR_BLK)))){
    tr_crit("tids_req_handler(): malloc failed.");
    return -1;
  }
  memset(resp->servers, 0, sizeof(TID_SRVR_BLK));
  resp->num_servers = 1;

  /* TBD -- Set up the server IP Address */

  if (!(req) || !(req->tidc_dh)) {
    tr_debug("tids_req_handler(): No client DH info.");
    return -1;
  }

  if ((!req->tidc_dh->p) || (!req->tidc_dh->g)) {
    tr_debug("tids_req_handler: NULL dh values.");
    return -1;
  }

  /* Generate the server DH block based on the client DH block */
  // fprintf(stderr, "Generating the server DH block.\n");
  // fprintf(stderr, "...from client DH block, dh_g = %s, dh_p = %s.\n", BN_bn2hex(req->tidc_dh->g), BN_bn2hex(req->tidc_dh->p));

  if (NULL == (resp->servers->aaa_server_dh = tr_create_matching_dh(NULL, 0, req->tidc_dh))) {
    tr_debug("tids_req_handler: Can't create server DH params.");
    return -1;
  }

  if (0 == inet_aton(tids->ipaddr, &(resp->servers->aaa_server_addr))) {
    tr_debug("tids_req_handler: inet_aton() failed.");
    return -1;
  }

  /* Set the key name */
  if (-1 == create_key_id(key_id, sizeof(key_id)))
    return -1;
  resp->servers->key_name = tr_new_name(key_id);

  /* Generate the server key */
  // fprintf(stderr, "Generating the server key.\n");

  if (0 > (s_keylen = tr_compute_dh_key(&s_keybuf, 
					req->tidc_dh->pub_key, 
				        resp->servers->aaa_server_dh))) {
    tr_debug("tids_req_handler: Key computation failed.");
    return -1;
  }
  if (0 != tr_dh_pub_hash(req,
			  &pub_digest, &pub_digest_len)) {
    tr_debug("tids_req_handler: Unable to digest client public key");
    return -1;
  }
  if (0 != handle_authorizations(req, pub_digest, pub_digest_len))
    return -1;
  if (NULL != insert_stmt) {
    int sqlite3_result;
    sqlite3_bind_text(insert_stmt, 1, key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(insert_stmt, 2, s_keybuf, s_keylen, SQLITE_TRANSIENT);
    sqlite3_bind_blob(insert_stmt, 3, pub_digest, pub_digest_len, SQLITE_TRANSIENT);
    sqlite3_result = sqlite3_step(insert_stmt);
    if (SQLITE_DONE != sqlite3_result)
      tr_crit("sqlite3: failed to write to database");
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

  talloc_set_log_stderr();
  /* Parse command-line arguments */ 
  if (argc != 5) {
    fprintf(stdout, "Usage: %s <ip-address> <gss-name> <hostname> <database-name>\n", argv[0]);
    exit(1);
  }

  /* Use standalone logging */
  tr_log_open();

  /* set logging levels */
  tr_log_threshold(LOG_CRIT);
  tr_console_threshold(LOG_DEBUG);

  ipaddr = (char *)argv[1];
  gssname = tr_new_name((char *) argv[2]);
  hostname = argv[3];
  if (SQLITE_OK != sqlite3_open(argv[4], &db)) {
    tr_crit("Error opening database %s", argv[4]);
    exit(1);
  }
  sqlite3_busy_timeout( db, 1000);
  sqlite3_prepare_v2(db, "insert into psk_keys (keyid, key, client_dh_pub) values(?, ?, ?)",
		     -1, &insert_stmt, NULL);
  sqlite3_prepare_v2(db, "insert into authorizations (client_dh_pub, coi, acceptor_realm, hostname, apc) values(?, ?, ?, ?, ?)",
		     -1, &authorization_insert, NULL);

  /* Create a TID server instance */
  if (NULL == (tids = tids_create())) {
    tr_crit("Unable to create TIDS instance, exiting.");
    return 1;
  }

  tids->ipaddr = ipaddr;

  /* Start-up the server, won't return unless there is an error. */
  rc = tids_start(tids, &tids_req_handler , auth_handler, hostname, TID_PORT, gssname);
  
  tr_crit("Error in tids_start(), rc = %d. Exiting.", rc);

  /* Clean-up the TID server instance */
  tids_destroy(tids);

  return 1;
}

