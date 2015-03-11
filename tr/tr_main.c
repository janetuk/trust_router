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
#include <jansson.h>

#include <tr.h>
#include <tr_filter.h>
#include <tid_internal.h>
#include <tr_config.h>
#include <tr_comm.h>
#include <tr_idp.h>
#include <tr_rp.h>
#include <tr_debug.h>

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
  tr_debug("tr_tidc_resp_handler: Response received (conn = %d)! Realm = %s, Community = %s.", ((TR_RESP_COOKIE *)resp_cookie)->orig_req->conn, resp->realm->buf, resp->comm->buf);
  req->resp_rcvd = 1;

  /* TBD -- handle concatentation of multiple responses to single req */
  tids_send_response(((TR_RESP_COOKIE *)resp_cookie)->tr->tids, 
		     ((TR_RESP_COOKIE *)resp_cookie)->orig_req, 
		     resp);
  
  return;
}

static int tr_tids_req_handler (TIDS_INSTANCE *tids,
		      TID_REQ *orig_req, 
		      TID_RESP *resp,
		      void *tr_in)
{
  TIDC_INSTANCE *tidc = NULL;
  TR_RESP_COOKIE resp_cookie;
  TR_AAA_SERVER *aaa_servers = NULL;
  TR_NAME *apc = NULL;
  TID_REQ *fwd_req = NULL;
  TR_COMM *cfg_comm = NULL;
  TR_COMM *cfg_apc = NULL;
  TR_INSTANCE *tr = (TR_INSTANCE *) tr_in;
  int oaction = TR_FILTER_ACTION_REJECT;
  int rc = 0;

  if ((!tids) || (!orig_req) || (!resp) ||  (!tr)) {
    tr_debug("tr_tids_req_handler: Bad parameters");
    return -1;
  }

  tr_debug("tr_tids_req_handler: Request received (conn = %d)! Realm = %s, Comm = %s", orig_req->conn, 
	 orig_req->realm->buf, orig_req->comm->buf);
  if (tids)
    tids->req_count++;

  /* Duplicate the request, so we can modify and forward it */
  if (NULL == (fwd_req = tid_dup_req(orig_req))) {
    tr_debug("tr_tids_req_handler: Unable to duplicate request.");
    return -1;
  }

  if (NULL == (cfg_comm = tr_comm_lookup(tids->cookie, orig_req->comm))) {
    tr_notice("tr_tids_req_hander: Request for unknown comm: %s.", orig_req->comm->buf);
    tids_send_err_response(tids, orig_req, "Unknown community");
    return -1;
  }

  /* Check that the rp_realm matches the filter for the GSS name that 
   * was received. */

  if ((!(tr)->rp_gss) || 
      (!(tr)->rp_gss->filter)) {
    tr_notice("tr_tids_req_handler: No GSS name for incoming request.");
    tids_send_err_response(tids, orig_req, "No GSS name for request");
    return -1;
  }

  if ((TR_FILTER_NO_MATCH == tr_filter_process_rp_permitted(orig_req->rp_realm, (tr)->rp_gss->filter, orig_req->cons, &fwd_req->cons, &oaction)) ||
      (TR_FILTER_ACTION_REJECT == oaction)) {
    tr_notice("tr_tids_req_handler: RP realm (%s) does not match RP Realm filter for GSS name", orig_req->rp_realm->buf);
    tids_send_err_response(tids, orig_req, "RP Realm filter error");
    return -1;
  }
  /* Check that the rp_realm is a member of the community in the request */
  if (NULL == (tr_find_comm_rp(cfg_comm, orig_req->rp_realm))) {
    tr_notice("tr_tids_req_handler: RP Realm (%s) not member of community (%s).", orig_req->rp_realm->buf, orig_req->comm->buf);
    tids_send_err_response(tids, orig_req, "RP COI membership error");
    return -1;
  }

  /* Map the comm in the request from a COI to an APC, if needed */
  if (TR_COMM_COI == cfg_comm->type) {
    tr_debug("tr_tids_req_handler: Community was a COI, switching.");
    /* TBD -- In theory there can be more than one?  How would that work? */
    if ((!cfg_comm->apcs) || (!cfg_comm->apcs->id)) {
      tr_notice("No valid APC for COI %s.", orig_req->comm->buf);
      tids_send_err_response(tids, orig_req, "No valid APC for community");
      return -1;
    }
    apc = tr_dup_name(cfg_comm->apcs->id);

    /* Check that the APC is configured */
    if (NULL == (cfg_apc = tr_comm_lookup(tids->cookie, apc))) {
      tr_notice("tr_tids_req_hander: Request for unknown comm: %s.", apc->buf);
      tids_send_err_response(tids, orig_req, "Unknown APC");
      return -1;
    }

    fwd_req->comm = apc;
    fwd_req->orig_coi = orig_req->comm;

    /* Check that rp_realm is a  member of this APC */
    if (NULL == (tr_find_comm_rp(cfg_apc, orig_req->rp_realm))) {
      tr_notice("tr_tids_req_hander: RP Realm (%s) not member of community (%s).", orig_req->rp_realm->buf, orig_req->comm->buf);
      tids_send_err_response(tids, orig_req, "RP APC membership error");
      return -1;
    }
  }

  /* Find the AAA server(s) for this request */
  if (NULL == (aaa_servers = tr_idp_aaa_server_lookup((TR_INSTANCE *)tids->cookie, 
						      orig_req->realm, 
						      orig_req->comm))) {
      tr_debug("tr_tids_req_handler: No AAA Servers for realm %s, defaulting.", orig_req->realm->buf);
      if (NULL == (aaa_servers = tr_default_server_lookup ((TR_INSTANCE *)tids->cookie,
							   orig_req->comm))) {
	tr_notice("tr_tids_req_handler: No default AAA servers, discarded.");
        tids_send_err_response(tids, orig_req, "No path to AAA Server(s) for realm");
        return -1;
      }
  } else {
    /* if we aren't defaulting, check idp coi and apc membership */
    if (NULL == (tr_find_comm_idp(cfg_comm, fwd_req->realm))) {
      tr_notice("tr_tids_req_handler: IDP Realm (%s) not member of community (%s).", orig_req->realm->buf, orig_req->comm->buf);
      tids_send_err_response(tids, orig_req, "IDP community membership error");
      return -1;
    }
    if ( cfg_apc && (NULL == (tr_find_comm_idp(cfg_apc, fwd_req->realm)))) {
      tr_notice("tr_tids_req_handler: IDP Realm (%s) not member of APC (%s).", orig_req->realm->buf, orig_req->comm->buf);
      tids_send_err_response(tids, orig_req, "IDP APC membership error");
      return -1;
    }
  }

  /* send a TID request to the AAA server(s), and get the answer(s) */
  /* TBD -- Handle multiple servers */

  if (cfg_apc)
    fwd_req->expiration_interval = cfg_apc->expiration_interval;
  else fwd_req->expiration_interval = cfg_comm->expiration_interval;
  /* Create a TID client instance */
  if (NULL == (tidc = tidc_create())) {
    tr_crit("tr_tids_req_hander: Unable to allocate TIDC instance.");
    tids_send_err_response(tids, orig_req, "Memory allocation failure");
    return -1;
  }
  /* Use the DH parameters from the original request */
  /* TBD -- this needs to be fixed when we handle more than one req per conn */
  tidc->client_dh = orig_req->tidc_dh;

  /* Save information about this request for the response */
  resp_cookie.tr = tr;
  resp_cookie.orig_req = orig_req;

  /* Set-up TID connection */
  if (-1 == (fwd_req->conn = tidc_open_connection(tidc, 
						  aaa_servers->hostname->buf,
						  TID_PORT,
					      &(fwd_req->gssctx)))) {
    tr_notice("tr_tids_req_handler: Error in tidc_open_connection.");
    tids_send_err_response(tids, orig_req, "Can't open connection to next hop TIDS");
    return -1;
  };

  /* Send a TID request */
  if (0 > (rc = tidc_fwd_request(tidc, fwd_req, &tr_tidc_resp_handler, (void *)&resp_cookie))) {
    tr_notice("Error from tidc_fwd_request, rc = %d.", rc);
    tids_send_err_response(tids, orig_req, "Can't forward request to next hop TIDS");
    tid_req_free(orig_req);
    return -1;
  }
    
  tid_req_free(orig_req);
  return 0;
}

static int tr_tids_gss_handler(gss_name_t client_name, TR_NAME *gss_name,
			void *tr_in)
{
  TR_RP_CLIENT *rp;
  TR_INSTANCE *tr = (TR_INSTANCE *) tr_in;

  if ((!client_name) || (!gss_name) || (!tr)) {
    tr_debug("tr_tidc_gss_handler: Bad parameters.");
    return -1;
  }
  
  /* look up the RP client matching the GSS name */
  if ((NULL == (rp = tr_rp_client_lookup(tr, gss_name)))) {
    tr_debug("tr_tids_gss_handler: Unknown GSS name %s", gss_name->buf);
    return -1;
  }

  /* Store the rp client in the TR_INSTANCE structure for now... 
   * TBD -- fix me for new tasking model. */
  (tr)->rp_gss = rp;
  tr_debug("Client's GSS Name: %s", gss_name->buf);

  return 0;
}


int main (int argc, const char *argv[])
{
  TR_INSTANCE *tr = NULL;
  struct dirent **cfg_files = NULL;
  TR_CFG_RC rc = TR_CFG_SUCCESS;	/* presume success */
  int err = 0, n = 0;;

  /* parse command-line arguments? -- TBD */

  /* create a Trust Router instance */
  if (NULL == (tr = tr_create())) {
    tr_crit("Unable to create Trust Router instance, exiting.");
    return 1;
  }

  /* find the configuration files */
  if (0 == (n = tr_find_config_files(&cfg_files))) {
    tr_crit("Can't locate configuration files, exiting.");
    exit(1);
  }

  if (TR_CFG_SUCCESS != tr_parse_config(tr, n, cfg_files)) {
    tr_crit("Error decoding configuration information, exiting.");
    exit(1);
  }

  /* apply initial configuration */
  if (TR_CFG_SUCCESS != (rc = tr_apply_new_config(tr))) {
    tr_crit("Error applying configuration, rc = %d.", rc);
    exit(1);
  }

  /* initialize the trust path query server instance */
  if (0 == (tr->tids = tids_create ())) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    exit(1);
  }

  /* start the trust path query server, won't return unless fatal error. */
  if (0 != (err = tids_start(tr->tids, &tr_tids_req_handler, &tr_tids_gss_handler, tr->active_cfg->internal->hostname, tr->active_cfg->internal->tids_port, (void *)tr))) {
    tr_crit("Error from Trust Path Query Server, err = %d.", err);
    exit(err);
  }

  tids_destroy(tr->tids);
  tr_destroy(tr);
  exit(0);
}
