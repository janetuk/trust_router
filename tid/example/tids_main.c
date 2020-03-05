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
#include <string.h>
#include <stdlib.h>
#include <talloc.h>
#include <sqlite3.h>
#include <argp.h>
#include <poll.h>
#include <unistd.h>
#include <netdb.h>

#include <tr_debug.h>
#include <tr_util.h>
#include <tid_internal.h>
#include <trust_router/tr_constraint.h>
#include <trust_router/tr_dh.h>
#include <openssl/rand.h>
#include <ssl-compat.h>

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
  if (-1 == RAND_bytes(rand_buf, bin_len))
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
    int i;
    char* s;
    if (strchr(wc[lc], '%')) {
      *error = talloc_asprintf( req, "Constraint match `%s' is not appropriate for SQL",
				  wc[lc]);
      return -1;
    }
    /* create a writeable copy */
    s = talloc_strdup(req, wc[lc]);
    /* replace '*' with '%', and '?' with '_' */
    for (i=0; i<strlen(s); i++) {
      if ('*' == s[i])
        s[i] = '%';
      else if ('?' == s[i])
        s[i] = '_';
    }
    wc[lc] = s;
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

  /* Not having a match does not mean an error, but a failed authorisation.
   * Hence, return 0 without inserting anything in the DB for these two cases. */
  if (0 != tr_constraint_set_get_match_strings(req,
					       intersected, "domain",
					       &domain_wc, &domain_len)) {
        tr_debug("warn: tr_constraint_set_get_match_strings for domain constraints returned != 0");
        return 0;
  }
  if (0 != tr_constraint_set_get_match_strings(req,
					       intersected, "realm",
					       &realm_wc, &realm_len)) {
        tr_debug("warn: tr_constraint_set_get_match_strings for realm constraints returned != 0");
        return 0;
  }
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
      sqlite3_clear_bindings(authorization_insert);
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
  unsigned char *pub_digest=NULL;
  size_t pub_digest_len;
  const BIGNUM *p = NULL, *g = NULL, *pub_key = NULL;
  gchar** ipaddrs = NULL, **ipaddr;

  tr_debug("tids_req_handler: Request received! target_realm = %s, community = %s", req->realm->buf, req->comm->buf);
  if (!(resp) || !resp) {
    tr_debug("tids_req_handler: No response structure.");
    return -1;
  }

  if (!(req) || !(req->tidc_dh)) {
    tr_debug("tids_req_handler(): No client DH info.");
    return -1;
  }

  DH_get0_pqg(req->tidc_dh, &p, NULL, &g);
  if ((!p) || (!g)) {
    tr_debug("tids_req_handler: NULL dh values.");
    return -1;
  }

  /* A AAA server might have more than one IP address. Iterate over them */
  for (ipaddrs = ipaddr = g_strsplit(tids->ipaddr, " ", 0); *ipaddr != NULL; ipaddr++ ) {
    /* Skip empty addresses */
    if (*ipaddr[0] == '\0') {
      tr_debug("tids_req_handler(): Skipping empty address");
      continue;
    }

    TID_SRVR_BLK *new_server = tid_srvr_blk_new(resp);
    tid_srvr_blk_add(resp->servers, new_server);

    /* Allocate a new server block */
    if (NULL==resp->servers) {
      tr_crit("tids_req_handler(): unable to allocate server block.");
      return -1;
    }

    /* Generate the server DH block based on the client DH block */
    if (NULL == (new_server->aaa_server_dh = tr_create_matching_dh(NULL, 0, req->tidc_dh))) {
      tr_debug("tids_req_handler: Can't create server DH params.");
      return -1;
    }
    new_server->aaa_server_addr = talloc_strdup(new_server, *ipaddr);

    /* Set the key name */
    if (-1 == create_key_id(key_id, sizeof(key_id)))
      return -1;
    new_server->key_name = tr_new_name(key_id);

    /* Generate the server key */
    DH_get0_key(req->tidc_dh, &pub_key, NULL);
    if (0 > (s_keylen = tr_compute_dh_key(&s_keybuf, pub_key, new_server->aaa_server_dh))) {
      tr_debug("tids_req_handler: Key computation failed.");
      return -1;
    }
    if (0 != tr_dh_pub_hash(req, &pub_digest, &pub_digest_len)) {
      tr_debug("tids_req_handler: Unable to digest client public key");
      return -1;
    }
    if (0 != handle_authorizations(req, pub_digest, pub_digest_len))
      return -1;
    tid_srvr_blk_set_path(new_server, (TID_PATH *)(req->path));

    if (req->expiration_interval < 1)
      req->expiration_interval = 1;
#ifdef HAVE_DATETIME
    new_server->key_expiration = g_get_real_time() / 1000000 + req->expiration_interval * 60 /*in minutes*/;
#else
    g_get_current_time(&new_server->key_expiration);
    new_server->key_expiration.tv_sec += req->expiration_interval * 60 /*in minutes*/;
#endif

    if (NULL != insert_stmt) {
      int sqlite3_result;
#ifdef HAVE_DATETIME
      GDateTime *dt = g_date_time_new_from_unix_utc(new_server->key_expiration);
      gchar *expiration_str = g_date_time_format_iso8601 (dt);
      g_date_time_unref (dt);
#else
      gchar *expiration_str = g_time_val_to_iso8601(&new_server->key_expiration);
#endif
      sqlite3_bind_text(insert_stmt, 1, key_id, -1, SQLITE_TRANSIENT);
      sqlite3_bind_blob(insert_stmt, 2, s_keybuf, s_keylen, SQLITE_TRANSIENT);
      sqlite3_bind_blob(insert_stmt, 3, pub_digest, pub_digest_len, SQLITE_TRANSIENT);
      sqlite3_bind_text(insert_stmt, 4, expiration_str, -1, SQLITE_TRANSIENT);
      g_free(expiration_str); /* bind_text already made its own copy */
      sqlite3_result = sqlite3_step(insert_stmt);
      if (SQLITE_DONE != sqlite3_result)
        tr_crit("sqlite3: failed to write to database");
      sqlite3_reset(insert_stmt);
      sqlite3_clear_bindings(insert_stmt);
    }
    if (s_keybuf!=NULL)
      free(s_keybuf);

    if (pub_digest!=NULL)
      talloc_free(pub_digest);
  }

  if (ipaddrs != NULL)
    g_strfreev(ipaddrs);

  return s_keylen;
}

static int auth_handler(gss_name_t gss_name, TR_NAME *client,
			void *expected_client)
{
  TR_NAME *expected_client_trname = (TR_NAME*) expected_client;
  int result=tr_name_cmp(client, expected_client_trname);
  if (result != 0) {
    tr_notice("Auth denied for incorrect gss-name ('%.*s' requested, expected '%.*s').",
              client->len, client->buf,
              expected_client_trname->len, expected_client_trname->buf);
  }
  return result;
}

static void print_version_info(void)
{
  tr_info("Moonshot TID Server %s\n\n", PACKAGE_VERSION);
}

/* command-line option setup */

/* argp global parameters */
const char *argp_program_bug_address=PACKAGE_BUGREPORT; /* bug reporting address */

/* doc strings */
static const char doc[] = "Starts a TID server that accepts requests coming from a "
"Trust Router server named TRUST_ROUTER_NAME (e.g. trustrouter@test.apc).\n";

static const char arg_doc[]="TRUST_ROUTER_NAME"; /* string describing arguments, if any */

/* define the options here. Fields are:
 * { long-name, short-name, variable name, options, help description } */
static const struct argp_option cmdline_options[] = {
  { "ip", 'i', "IP_ADDRESS[:PORT]", 0,
    "IP address/hostname and optionally port (separated by #) of the AAA server. "
    "This is the value included in TID response messages. Defaults to the configured hostname."},
  { "hostname", 'h', "HOSTNAME", 0,
    "Hostname of the TIDS server. Used for generating the TIDS GSS acceptor name. Defaults to the current hostname."},
  { "port", 'p', "PORT", 0, "Port where the TID server listen for requets. Defaults to 12309"},
  { "database", 'd', "FILE", 0,
    "Path to the SQlite3 database where keys are stored. Defaults to /var/lib/trust_router/keys"},
  { "version", 'v', NULL, 0, "Print version information and exit"},
  { NULL }
};

/* structure for communicating with option parser */
struct cmdline_args {
  char *ip_address;
  char *gss_name;
  char *hostname;
  char *database_name;
  int port;
};

/* parser for individual options - fills in a struct cmdline_args */
static error_t parse_option(int key, char *arg, struct argp_state *state)
{
  /* get a shorthand to the command line argument structure, part of state */
  struct cmdline_args *arguments=state->input;

  switch (key) {
  case ARGP_KEY_ARG: /* handle argument (not option) */
    /* Too many arguments. */
    if (state->arg_num > 1)
      argp_usage (state);
    arguments->gss_name = arg;
    break;

  case ARGP_KEY_END: /* no more arguments */
    /* not enough arguments encountered */
    if (state->arg_num < 1) {
      argp_usage(state);
    }
    break;

  case 'v':
    print_version_info();
    exit(0);

  case 'i':
    arguments->ip_address = arg;
    break;

  case 'p':
    arguments->port = atoi(arg);
    break;

  case 'h':
    arguments->hostname = arg;
    break;

  case 'd':
    arguments->database_name = arg;
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
  TIDS_INSTANCE *tids = NULL;
  TR_NAME *gssname = NULL;

  struct cmdline_args opts={"", "", "", "", 0};

  /* parse the command line*/
  argp_parse(&argp, argc, argv, 0, 0, &opts);

  /* set default hostname if not passed */
  if (strcmp(opts.hostname, "") == 0 || strcmp(opts.hostname, "auto") == 0) {
    opts.hostname = malloc(1024);
    gethostname(opts.hostname, 1024);
  }

  /* set ip address if not passed */
  if (strcmp(opts.ip_address, "") == 0 || strcmp(opts.ip_address, "auto") == 0) {
      opts.ip_address = opts.hostname;
  }

  if (strcmp(opts.database_name, "") == 0 || strcmp(opts.database_name, "auto") == 0)
    opts.database_name = "/var/lib/trust_router/keys";

  if (opts.port == 0)
    opts.port = TID_PORT;

  tr_debug("--------- Running with ---------------");
  tr_debug("Trust Router name: %s", opts.gss_name);
  tr_debug("Hostname:          %s", opts.hostname);
  tr_debug("IP address:        %s", opts.ip_address);
  tr_debug("Port:              %d", opts.port);
  tr_debug("PSK database:      %s", opts.database_name);
  tr_debug("---------------------------------------");
  print_version_info();

  talloc_set_log_stderr();

  /* Use standalone logging */
  tr_log_open();

  /* set logging levels */
  tr_log_threshold(LOG_CRIT);
  tr_console_threshold(LOG_DEBUG);

  gssname = tr_new_name(opts.gss_name);
  if (SQLITE_OK != sqlite3_open(opts.database_name, &db)) {
    tr_crit("Error opening database %s", opts.database_name);
    exit(1);
  }
  sqlite3_busy_timeout( db, 1000);
  sqlite3_prepare_v2(db, "insert into psk_keys_tab (keyid, key, client_dh_pub, key_expiration) values(?, ?, ?, ?)",
		     -1, &insert_stmt, NULL);
  sqlite3_prepare_v2(db, "insert into authorizations (client_dh_pub, coi, acceptor_realm, hostname, apc) values(?, ?, ?, ?, ?)",
		     -1, &authorization_insert, NULL);

  /* Create a TID server instance */
  if (NULL == (tids = tids_create())) {
    tr_crit("Unable to create TIDS instance, exiting.");
    return 1;
  }

  tids->ipaddr = opts.ip_address;
  (void) tids_start(tids, &tids_req_handler, auth_handler, opts.hostname, opts.port, gssname);

  /* Clean-up the TID server instance */
  tids_destroy(tids);

  return 1;
}

