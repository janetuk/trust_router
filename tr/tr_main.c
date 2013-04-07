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
#include <jansson.h>

#include <tr.h>
#include <trust_router/tid.h>
#include <tr_config.h>
#include <tr_idp.h>

/* Structure to hold TR instance and original request in one cookie */
typedef struct tr_resp_cookie {
  TR_INSTANCE *tr;
  TID_REQ *orig_req;
} TR_RESP_COOKIE;

static void tr_tidc_resp_handler (TIDC_INSTANCE *tidc, 
			TID_REQ *req,
			TID_RESP *resp, 
			void *resp_cookie) 
{
  fprintf(stderr, "tr_tidc_resp_handler: Response received! Realm = %s, Community = %s.\n", resp->realm->buf, resp->comm->buf);
  req->resp_rcvd = 1;

  /* TBD -- handle concatentation of multiple responses to single req */
  tids_send_response(((TR_RESP_COOKIE *)resp_cookie)->tr->tids, ((TR_RESP_COOKIE *)resp_cookie)->orig_req->conn, &((TR_RESP_COOKIE *)resp_cookie)->orig_req->gssctx, resp);
  
  return;
}

static int tr_tids_req_handler (TIDS_INSTANCE * tids,
		      TID_REQ *req, 
		      TID_RESP **resp,
		      void *tr)
{
  gss_ctx_id_t gssctx;
  TIDC_INSTANCE *tidc = NULL;
  TR_RESP_COOKIE resp_cookie;
  TR_AAA_SERVER *aaa_servers = NULL;
  int conn = 0;
  int rc;

  if ((!tids) || (!req) || (!resp) || (!(*resp))) {
    printf("tids_req_handler: Bad parameters\n");
    return -1;
  }

  printf("Request received! Realm = %s, Comm = %s\n", req->realm->buf, req->comm->buf);
  if (tids)
    tids->req_count++;

  /* find the AAA server(s) for this request */
  aaa_servers = tr_idp_aaa_server_lookup((TR_INSTANCE *)tids->cookie, req->realm, req->comm);
  /* send a TID request to the AAA server(s), and get the answer(s) */
  /* TBD -- Handle multiple servers */

  /* Create a TID client instance */
  if (NULL == (tidc = tidc_create())) {
    fprintf(stderr, "tr_tids_req_hander: Unable to allocate TIDC instance.\n");
    return -1;
  }

  /* Set-up TID connection */
  /* TBD -- version of open_connection that takes an inaddr */
  if (-1 == (conn = tidc_open_connection(tidc, inet_ntoa(aaa_servers->aaa_server_addr), &gssctx))) {
    printf("tr_tids_req_handler: Error in tidc_open_connection.\n");
    return -1;
  };

  /* Send a TID request */
  resp_cookie.tr = tr;
  resp_cookie.orig_req = req;

  /* TBD -- version of send request that takes TR_NAMES */
  if (0 > (rc = tidc_send_request(tidc, conn, gssctx, req->rp_realm->buf, req->realm->buf, req->comm->buf, &tr_tidc_resp_handler, (void *)&resp_cookie))) {
    printf("Error in tidc_send_request, rc = %d.\n", rc);
    return -1;
  }
    
  return 0;
}

int main (int argc, const char *argv[])
{
  TR_INSTANCE *tr = NULL;
  struct dirent **cfg_files = NULL;
  json_t *jcfg = NULL;
  TR_CFG_RC rc = TR_CFG_SUCCESS;	/* presume success */
  int err = 0, n = 0;;

  /* parse command-line arguments -- TBD */

  /* create a Trust Router instance */
  if (NULL == (tr = tr_create())) {
    fprintf(stderr, "Unable to create Trust Router instance, exiting.\n");
    return 1;
  }

  /* find the configuration files */
  if (0 == (n = tr_find_config_files(&cfg_files))) {
    fprintf (stderr, "Can't locate configuration files, exiting.\n");
    exit(1);
  }

  /* read and parse initial configuration */
  if (NULL == (jcfg = tr_read_config (n, cfg_files))) {
    fprintf (stderr, "Error reading or parsing configuration files, exiting.\n");
    exit(1);
  }
  if (TR_CFG_SUCCESS != tr_parse_config(tr, jcfg)) {
    fprintf (stderr, "Error decoding configuration information, exiting.\n");
    exit(1);
  }

  /* apply initial configuration */
  if (TR_CFG_SUCCESS != (rc = tr_apply_new_config(tr))) {
    fprintf (stderr, "Error applying configuration, rc = %d.\n", rc);
    exit(1);
  }

  /* initialize the trust path query server instance */
  if (0 == (tr->tids = tids_create ())) {
    printf ("Error initializing Trust Path Query Server instance.\n");
    exit(1);
  }

  /* start the trust path query server, won't return unless error. */
  if (0 != (err = tids_start(tr->tids, &tr_tids_req_handler, (void *)tr))) {
    printf ("Error starting Trust Path Query Server, err = %d.\n", err);
    exit(err);
  }

  tids_destroy(tr->tids);
  tr_destroy(tr);
  exit(0);
}
