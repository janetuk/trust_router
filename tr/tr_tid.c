#include <tid_internal.h>
#include <tr_filter.h>
#include <tr_comm.h>
#include <tr_idp.h>
#include <tr_rp.h>
#include <tr_event.h>
#include <tr_debug.h>
#include <gsscon.h>
#include <tr_config.h>
#include <tr_tid.h>

/* Structure to hold TR instance and original request in one cookie */
typedef struct tr_resp_cookie {
  TIDS_INSTANCE *tids;
  TID_REQ *orig_req;
} TR_RESP_COOKIE;

/* hold a tids instance and a config manager */
struct tr_tids_event_cookie {
  TIDS_INSTANCE *tids;
  TR_CFG_MGR *cfg_mgr;
};


static void tr_tidc_resp_handler (TIDC_INSTANCE *tidc, 
                                  TID_REQ *req,
                                  TID_RESP *resp, 
                                  void *resp_cookie)
{
  tr_debug("tr_tidc_resp_handler: Response received (conn = %d)! Realm = %s, Community = %s.", ((TR_RESP_COOKIE *)resp_cookie)->orig_req->conn, resp->realm->buf, resp->comm->buf);
  req->resp_rcvd = 1;

  /* TBD -- handle concatentation of multiple responses to single req */
  tids_send_response(((TR_RESP_COOKIE *)resp_cookie)->tids, 
		     ((TR_RESP_COOKIE *)resp_cookie)->orig_req, 
		     resp);
  
  return;
}

static int tr_tids_req_handler (TIDS_INSTANCE *tids,
                                TID_REQ *orig_req, 
                                TID_RESP *resp,
                                void *cookie_in)
{
  TIDC_INSTANCE *tidc = NULL;
  TR_RESP_COOKIE resp_cookie;
  TR_AAA_SERVER *aaa_servers = NULL;
  TR_NAME *apc = NULL;
  TID_REQ *fwd_req = NULL;
  TR_COMM *cfg_comm = NULL;
  TR_COMM *cfg_apc = NULL;
  int oaction = TR_FILTER_ACTION_REJECT;
  int rc = 0;
  time_t expiration_interval;
  struct tr_tids_event_cookie *cookie=(struct tr_tids_event_cookie *)cookie_in;
  TR_CFG_MGR *cfg_mgr=cookie->cfg_mgr;

  if ((!tids) || (!orig_req) || (!resp)) {
    tr_debug("tr_tids_req_handler: Bad parameters");
    return -1;
  }

  tr_debug("tr_tids_req_handler: Request received (conn = %d)! Realm = %s, Comm = %s", orig_req->conn, 
           orig_req->realm->buf, orig_req->comm->buf);
  tids->req_count++;

  /* Duplicate the request, so we can modify and forward it */
  if (NULL == (fwd_req = tid_dup_req(orig_req))) {
    tr_debug("tr_tids_req_handler: Unable to duplicate request.");
    return -1;
  }

  if (NULL == (cfg_comm = tr_comm_lookup(cfg_mgr->active->comms, orig_req->comm))) {
    tr_notice("tr_tids_req_hander: Request for unknown comm: %s.", orig_req->comm->buf);
    tids_send_err_response(tids, orig_req, "Unknown community");
    return -1;
  }

  /* Check that the rp_realm matches the filter for the GSS name that 
   * was received. */

  if ((!tids->rp_gss) || 
      (!tids->rp_gss->filter)) {
    tr_notice("tr_tids_req_handler: No GSS name for incoming request.");
    tids_send_err_response(tids, orig_req, "No GSS name for request");
    return -1;
  }

  if ((TR_FILTER_NO_MATCH == tr_filter_process_rp_permitted(orig_req->rp_realm,
                                                            tids->rp_gss->filter,
                                                            orig_req->cons,
                                                           &fwd_req->cons,
                                                           &oaction)) ||
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
    if (NULL == (cfg_apc = tr_comm_lookup(cfg_mgr->active->comms, apc))) {
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
  if (NULL == (aaa_servers = tr_idp_aaa_server_lookup(cfg_mgr->active->idp_realms, 
                                                      orig_req->realm, 
                                                      orig_req->comm))) {
    tr_debug("tr_tids_req_handler: No AAA Servers for realm %s, defaulting.", orig_req->realm->buf);
    if (NULL == (aaa_servers = tr_default_server_lookup (cfg_mgr->active->default_servers,
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
    expiration_interval = cfg_apc->expiration_interval;
  else expiration_interval = cfg_comm->expiration_interval;
  if (fwd_req->expiration_interval)
    fwd_req->expiration_interval =  (expiration_interval < fwd_req->expiration_interval) ? expiration_interval : fwd_req->expiration_interval;
  else fwd_req->expiration_interval = expiration_interval;
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
  resp_cookie.tids = tids;
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
                               void *data)
{
  TR_RP_CLIENT *rp;
  struct tr_tids_event_cookie *cookie=(struct tr_tids_event_cookie *)data;
  TIDS_INSTANCE *tids = cookie->tids;
  TR_CFG_MGR *cfg_mgr = cookie->cfg_mgr;

  if ((!client_name) || (!gss_name) || (!tids) || (!cfg_mgr)) {
    tr_debug("tr_tidc_gss_handler: Bad parameters.");
    return -1;
  }

  /* look up the RP client matching the GSS name */
  if ((NULL == (rp = tr_rp_client_lookup(cfg_mgr->active->rp_clients, gss_name)))) {
    tr_debug("tr_tids_gss_handler: Unknown GSS name %s", gss_name->buf);
    return -1;
  }

  /* Store the rp client */
  tids->rp_gss = rp;
  tr_debug("Client's GSS Name: %s", gss_name->buf);

  return 0;
}


/***** TIDS event handling *****/

/* called when a connection to the TIDS port is received */
static void tr_tids_event_cb(int listener, short event, void *arg)
{
  TIDS_INSTANCE *tids = (TIDS_INSTANCE *)arg;

  if (0==(event & EV_READ))
    tr_debug("tr_tids_event_cb: unexpected event on TIDS socket (event=0x%X)", event);
  else 
    tids_accept(tids, listener);
}

/* Configure the tids instance and set up its event handler.
 * Returns 0 on success, nonzero on failure. Fills in
 * *tids_event (which should be allocated by caller). */
int tr_tids_event_init(struct event_base *base,
                       TIDS_INSTANCE *tids,
                       TR_CFG_MGR *cfg_mgr,
                       struct tr_socket_event *tids_ev)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_tids_event_cookie *cookie=NULL;
  int retval=0;

  if (tids_ev == NULL) {
    tr_debug("tr_tids_event_init: Null tids_ev.");
    retval=1;
    goto cleanup;
  }

  /* Create the cookie for callbacks. We'll put it in the tids context, so it will
   * be cleaned up when tids is freed by talloc_free. */
  cookie=talloc(tmp_ctx, struct tr_tids_event_cookie);
  if (cookie == NULL) {
    tr_debug("tr_tids_event_init: Unable to allocate cookie.");
    retval=1;
    goto cleanup;
  }
  cookie->tids=tids;
  cookie->cfg_mgr=cfg_mgr;
  talloc_steal(tids, cookie);

  /* get a tids listener */
  tids_ev->sock_fd=tids_get_listener(tids,
                                     tr_tids_req_handler,
                                     tr_tids_gss_handler,
                                     cfg_mgr->active->internal->hostname,
                                     cfg_mgr->active->internal->tids_port,
                                     (void *)cookie);
  if (tids_ev->sock_fd < 0) {
    tr_crit("Error opening TID server socket.");
    retval=1;
    goto cleanup;
  }

  /* and its event */
  tids_ev->ev=event_new(base,
                        tids_ev->sock_fd,
                        EV_READ|EV_PERSIST,
                        tr_tids_event_cb,
                        (void *)tids);
  event_add(tids_ev->ev, NULL);

cleanup:
  talloc_free(tmp_ctx);
  return retval;
}
