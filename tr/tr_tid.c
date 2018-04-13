/*
 * Copyright (c) 2016, JANET(UK)
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

#include <talloc.h>

#include <trust_router/tr_dh.h>
#include <tid_internal.h>
#include <tr_filter.h>
#include <tr_comm.h>
#include <tr_idp.h>
#include <tr_rp.h>
#include <tr_event.h>
#include <tr_debug.h>
#include <gsscon.h>
#include <trp_internal.h>
#include <tr_config.h>
#include <tr_mq.h>
#include <tr_util.h>
#include <tr_tid.h>

/* Structure to hold data for the tid response callback */
typedef struct tr_resp_cookie {
  int thread_id;
  TID_RESP *resp;
} TR_RESP_COOKIE;

/* hold a tids instance and a config manager */
struct tr_tids_event_cookie {
  TIDS_INSTANCE *tids;
  TR_CFG_MGR *cfg_mgr;
  TRPS_INSTANCE *trps;
};

static void tr_tidc_resp_handler(TIDC_INSTANCE *tidc, 
                                 TID_REQ *req,
                                 TID_RESP *resp, 
                                 void *resp_cookie)
{
  TR_RESP_COOKIE *cookie=talloc_get_type_abort(resp_cookie, TR_RESP_COOKIE);

  tr_debug("tr_tidc_resp_handler: Response received! Realm = %s, Community = %s, result = %s.",
           resp->realm->buf,
           resp->comm->buf,
           (TID_SUCCESS==resp->result)?"success":"error");

  if (resp->error_path!=NULL)
    tr_debug("tr_tids_resp_handler: error_path is set.");
  cookie->resp=tid_resp_dup(cookie, resp);
}

/* data for AAA req forwarding threads */
struct tr_tids_fwd_cookie {
  int thread_id;
  pthread_mutex_t mutex; /* lock on the mq (separate from the locking within the mq, see below) */
  TR_MQ *mq; /* messages from thread to main process; set to NULL to disable response */
  TR_NAME *aaa_hostname;
  DH *dh_params;
  TID_REQ *fwd_req; /* the req to duplicate */
};

static int tr_tids_fwd_cookie_destructor(void *obj)
{
  struct tr_tids_fwd_cookie *c=talloc_get_type_abort(obj, struct tr_tids_fwd_cookie);
  if (c->aaa_hostname!=NULL)
    tr_free_name(c->aaa_hostname);
  if (c->dh_params!=NULL)
    tr_destroy_dh_params(c->dh_params);
  return 0;
}

/* Block until we get the lock, returns 0 on success.
 * The mutex is used to protect changes to the mq pointer in
 * a thread's cookie. The master thread sets this to null to indicate
 * that it has abandoned the thread and the message queue is no longer
 * valid. This is unrelated to the locking in the message queue
 * implementation itself. */
static int tr_tids_fwd_get_mutex(struct tr_tids_fwd_cookie *cookie)
{
  if (cookie==NULL)
    return -1;

  return (pthread_mutex_lock(&(cookie->mutex)));
}

static int tr_tids_fwd_release_mutex(struct tr_tids_fwd_cookie *cookie)
{
  if (cookie==NULL)
    return -1;

  return (pthread_mutex_unlock(&(cookie->mutex)));
}

/* values for messages */
#define TR_TID_MQMSG_SUCCESS "tid success"
#define TR_TID_MQMSG_FAILURE "tid failure"

/* Thread main for sending and receiving a request to a single AAA server */
static void *tr_tids_req_fwd_thread(void *arg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_tids_fwd_cookie *args=talloc_get_type_abort(arg, struct tr_tids_fwd_cookie);
  TIDC_INSTANCE *tidc=tidc_create();
  TR_MQ_MSG *msg=NULL;
  TR_RESP_COOKIE *cookie=NULL;
  int rc=0;
  int success=0;

  talloc_steal(tmp_ctx, args); /* take responsibility for the cookie */

  if (tidc!=NULL)
    talloc_steal(tmp_ctx, tidc);

  /* create the cookie we will use for our response */
  cookie=talloc(tmp_ctx, TR_RESP_COOKIE);
  if (cookie==NULL) {
    tr_notice("tr_tids_req_fwd_thread: unable to allocate response cookie.");
    success=0;
    goto cleanup;
  }
  cookie->thread_id=args->thread_id;
  tr_debug("tr_tids_req_fwd_thread: thread %d started.", cookie->thread_id);

  /* Create a TID client instance */
  if (tidc==NULL) {
    tr_crit("tr_tids_req_fwd_thread: Unable to allocate TIDC instance.");
    /*tids_send_err_response(tids, orig_req, "Memory allocation failure");*/
    /* TODO: encode reason for failure */
    success=0;
    goto cleanup;
  }

  /* Set-up TID connection */
  if (-1==(args->fwd_req->conn = tidc_open_connection(tidc, 
                                                      args->aaa_hostname->buf,
                                                      TID_PORT, /* TODO: make this configurable */
                                                     &(args->fwd_req->gssctx)))) {
    tr_notice("tr_tids_req_fwd_thread: Error in tidc_open_connection.");
    /* tids_send_err_response(tids, orig_req, "Can't open connection to next hop TIDS"); */
    /* TODO: encode reason for failure */
    success=0;
    goto cleanup;
  };
  tr_debug("tr_tids_req_fwd_thread: thread %d opened TID connection to %s.",
           cookie->thread_id,
           args->aaa_hostname->buf);

  /* Send a TID request. */
  if (0 > (rc = tidc_fwd_request(tidc, args->fwd_req, tr_tidc_resp_handler, (void *)cookie))) {
    tr_notice("Error from tidc_fwd_request, rc = %d.", rc);
    success=0;
    goto cleanup;
  }
  /* cookie->resp should now contain our copy of the response */
  success=1;
  tr_debug("tr_tids_req_fwd_thread: thread %d received response.");

cleanup:
  /* Notify parent thread of the response, if it's still listening. */
  if (0!=tr_tids_fwd_get_mutex(args)) {
    tr_notice("tr_tids_req_fwd_thread: thread %d unable to acquire mutex.", cookie->thread_id);
  } else if (NULL!=args->mq) {
    /* mq is still valid, so we can queue our response */
    tr_debug("tr_tids_req_fwd_thread: thread %d using valid msg queue.", cookie->thread_id);
    if (success)
      msg=tr_mq_msg_new(tmp_ctx, TR_TID_MQMSG_SUCCESS, TR_MQ_PRIO_NORMAL);
    else
      msg=tr_mq_msg_new(tmp_ctx, TR_TID_MQMSG_FAILURE, TR_MQ_PRIO_NORMAL);

    if (msg==NULL)
      tr_notice("tr_tids_req_fwd_thread: thread %d unable to allocate response msg.", cookie->thread_id);

    tr_mq_msg_set_payload(msg, (void *)cookie, NULL);
    if (NULL!=cookie)
      talloc_steal(msg, cookie); /* attach this to the msg so we can forget about it */
    tr_mq_add(args->mq, msg);
    talloc_steal(NULL, args); /* take out of our tmp_ctx; master thread now responsible for freeing */
    tr_debug("tr_tids_req_fwd_thread: thread %d queued response message.", cookie->thread_id);
    if (0!=tr_tids_fwd_release_mutex(args))
      tr_notice("tr_tids_req_fwd_thread: Error releasing mutex.");
  }

  talloc_free(tmp_ctx);
  return NULL;
}

/* Merges r2 into r1 if they are compatible. */
static TID_RC tr_tids_merge_resps(TID_RESP *r1, TID_RESP *r2)
{
  /* ensure these are compatible replies */
  if ((r1->result!=TID_SUCCESS) || (r2->result!=TID_SUCCESS))
    return TID_ERROR;

  if ((0!=tr_name_cmp(r1->rp_realm, r2->rp_realm)) ||
      (0!=tr_name_cmp(r1->realm, r2->realm)) ||
      (0!=tr_name_cmp(r1->comm, r2->comm)))
    return TID_ERROR;

  tid_srvr_blk_add(r1->servers, tid_srvr_blk_dup(r1, r2->servers));
  return TID_SUCCESS;
}

/**
 * Process a TID request
 *
 * Return value of -1 means to send a TID_ERROR response. Fill in resp->err_msg or it will
 * be returned as a generic error.
 *
 * @param tids
 * @param orig_req
 * @param resp
 * @param cookie_in
 * @return
 */
static int tr_tids_req_handler(TIDS_INSTANCE *tids,
                               TID_REQ *orig_req, 
                               TID_RESP *resp,
                               void *cookie_in)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_AAA_SERVER *aaa_servers=NULL, *this_aaa=NULL;
  int n_aaa=0;
  int idp_shared=0;
  TR_AAA_SERVER_ITER *aaa_iter=NULL;
  pthread_t aaa_thread[TR_TID_MAX_AAA_SERVERS];
  struct tr_tids_fwd_cookie *aaa_cookie[TR_TID_MAX_AAA_SERVERS]={NULL};
  TID_RESP *aaa_resp[TR_TID_MAX_AAA_SERVERS]={NULL};
  TR_RP_CLIENT *rp_client=NULL;
  TR_RP_CLIENT_ITER *rpc_iter=NULL;
  TR_NAME *apc = NULL;
  TID_REQ *fwd_req = NULL;
  TR_COMM *cfg_comm = NULL;
  TR_COMM *cfg_apc = NULL;
  TR_FILTER_ACTION oaction = TR_FILTER_ACTION_REJECT;
  time_t expiration_interval=0;
  struct tr_tids_event_cookie *cookie=talloc_get_type_abort(cookie_in, struct tr_tids_event_cookie);
  TR_CFG_MGR *cfg_mgr=cookie->cfg_mgr;
  TRPS_INSTANCE *trps=cookie->trps;
  TRP_ROUTE *route=NULL;
  TR_MQ *mq=NULL;
  TR_MQ_MSG *msg=NULL;
  unsigned int n_responses=0;
  unsigned int n_failed=0;
  struct timespec ts_abort={0};
  unsigned int resp_frac_numer=cfg_mgr->active->internal->tid_resp_numer;
  unsigned int resp_frac_denom=cfg_mgr->active->internal->tid_resp_denom;
  TR_RESP_COOKIE *payload=NULL;
  TR_FILTER_TARGET *target=NULL;
  int ii=0;
  int retval=-1;

  if ((!tids) || (!orig_req) || (!resp)) {
    tr_debug("tr_tids_req_handler: Bad parameters");
    retval=-1;
    goto cleanup;
  }

  tr_debug("tr_tids_req_handler: Request received (conn = %d)! Realm = %s, Comm = %s", orig_req->conn, 
           orig_req->realm->buf, orig_req->comm->buf);
  tids->req_count++;

  /* Duplicate the request, so we can modify and forward it */
  if (NULL == (fwd_req=tid_dup_req(orig_req))) {
    tr_debug("tr_tids_req_handler: Unable to duplicate request.");
    retval=-1; /* response will be a generic internal error */
    goto cleanup;
  }
  talloc_steal(tmp_ctx, fwd_req);

  if (NULL == (cfg_comm=tr_comm_table_find_comm(cfg_mgr->active->ctable, orig_req->comm))) {
    tr_notice("tr_tids_req_hander: Request for unknown comm: %s.", orig_req->comm->buf);
    tid_resp_set_err_msg(resp, tr_new_name("Unknown community"));
    retval=-1;
    goto cleanup;
  }

  /* We now need to apply the filters associated with the RP client handing us the request.
   * It is possible (or even likely) that more than one client is associated with the GSS
   * name we got from the authentication. We will apply all of them in an arbitrary order.
   * For this to result in well-defined behavior, either only accept or only reject filter
   * lines should be used, or a unique GSS name must be given for each RP realm. */

  if (!tids->gss_name) {
    tr_notice("tr_tids_req_handler: No GSS name for incoming request.");
    tid_resp_set_err_msg(resp, tr_new_name("No GSS name for request"));
    retval=-1;
    goto cleanup;
  }

  /* Keep original constraints, may add more from the filter. These will be added to orig_req as
   * well. Need to verify that this is acceptable behavior, but it's what we've always done. */
  fwd_req->cons=orig_req->cons;

  target=tr_filter_target_tid_req(tmp_ctx, orig_req);
  if (target==NULL) {
    tr_crit("tid_req_handler: Unable to allocate filter target, cannot apply filter!");
    tid_resp_set_err_msg(resp, tr_new_name("Incoming TID request filter error"));
    retval=-1;
    goto cleanup;
  }

  rpc_iter=tr_rp_client_iter_new(tmp_ctx);
  if (rpc_iter==NULL) {
    tr_err("tid_req_handler: Unable to allocate RP client iterator.");
    retval=-1;
    goto cleanup;
  }
  for (rp_client=tr_rp_client_iter_first(rpc_iter, cfg_mgr->active->rp_clients);
       rp_client != NULL;
       rp_client=tr_rp_client_iter_next(rpc_iter)) {

    if (!tr_gss_names_matches(rp_client->gss_names, tids->gss_name))
      continue; /* skip any that don't match the GSS name */

    if (TR_FILTER_MATCH == tr_filter_apply(target,
                                           tr_filter_set_get(rp_client->filters,
                                                             TR_FILTER_TYPE_TID_INBOUND),
                                           &(fwd_req->cons),
                                           &oaction))
      break; /* Stop looking, oaction is set */
  }

  /* We get here whether or not a filter matched. If tr_filter_apply() doesn't match, it returns
   * a default action of reject, so we don't have to check why we exited the loop. */
  if (oaction != TR_FILTER_ACTION_ACCEPT) {
    tr_notice("tr_tids_req_handler: Incoming TID request rejected by filter for GSS name", orig_req->rp_realm->buf);
    tid_resp_set_err_msg(resp, tr_new_name("Incoming TID request filter error"));
    retval = -1;
    goto cleanup;
  }

  /* Check that the rp_realm is a member of the community in the request */
  if (NULL == tr_comm_find_rp(cfg_mgr->active->ctable, cfg_comm, orig_req->rp_realm)) {
    tr_notice("tr_tids_req_handler: RP Realm (%s) not member of community (%s).", orig_req->rp_realm->buf, orig_req->comm->buf);
    tid_resp_set_err_msg(resp, tr_new_name("RP COI membership error"));
    retval=-1;
    goto cleanup;
  }

  /* Map the comm in the request from a COI to an APC, if needed */
  if (TR_COMM_COI == cfg_comm->type) {
    if (orig_req->orig_coi!=NULL) {
      tr_notice("tr_tids_req_handler: community %s is COI but COI to APC mapping already occurred. Dropping request.",
               orig_req->comm->buf);
      tid_resp_set_err_msg(resp, tr_new_name("Second COI to APC mapping would result, permitted only once."));
      retval=-1;
      goto cleanup;
    }
    
    tr_debug("tr_tids_req_handler: Community was a COI, switching.");
    /* TBD -- In theory there can be more than one?  How would that work? */
    if ((!cfg_comm->apcs) || (!cfg_comm->apcs->id)) {
      tr_notice("No valid APC for COI %s.", orig_req->comm->buf);
      tid_resp_set_err_msg(resp, tr_new_name("No valid APC for community"));
      retval=-1;
      goto cleanup;
    }
    apc = tr_dup_name(cfg_comm->apcs->id);

    /* Check that the APC is configured */
    if (NULL == (cfg_apc = tr_comm_table_find_comm(cfg_mgr->active->ctable, apc))) {
      tr_notice("tr_tids_req_hander: Request for unknown comm: %s.", apc->buf);
      tid_resp_set_err_msg(resp, tr_new_name("Unknown APC"));
      retval=-1;
      goto cleanup;
    }

    fwd_req->comm = apc;
    fwd_req->orig_coi = orig_req->comm;

    /* Check that rp_realm is a  member of this APC */
    if (NULL == (tr_comm_find_rp(cfg_mgr->active->ctable, cfg_apc, orig_req->rp_realm))) {
      tr_notice("tr_tids_req_hander: RP Realm (%s) not member of community (%s).", orig_req->rp_realm->buf, orig_req->comm->buf);
      tid_resp_set_err_msg(resp, tr_new_name("RP APC membership error"));
      retval=-1;
      goto cleanup;
    }
  }

  /* Look up the route for this community/realm. */
  tr_debug("tr_tids_req_handler: looking up route.");
  route=trps_get_selected_route(trps, orig_req->comm, orig_req->realm);
  if (route==NULL) {
    /* No route. Use default AAA servers if we have them. */
    tr_debug("tr_tids_req_handler: No route for realm %s, defaulting.", orig_req->realm->buf);
    if (NULL == (aaa_servers = tr_default_server_lookup(cfg_mgr->active->default_servers,
                                                        orig_req->comm))) {
      tr_notice("tr_tids_req_handler: No default AAA servers, discarded.");
      tid_resp_set_err_msg(resp, tr_new_name("No path to AAA Server(s) for realm"));
      retval = -1;
      goto cleanup;
    }
    idp_shared = 0;
  } else {
    /* Found a route. Determine the AAA servers or next hop address. */
    tr_debug("tr_tids_req_handler: found route.");
    if (trp_route_is_local(route)) {
      tr_debug("tr_tids_req_handler: route is local.");
      aaa_servers = tr_idp_aaa_server_lookup(cfg_mgr->active->ctable->idp_realms,
                                             orig_req->realm,
                                             orig_req->comm,
                                             &idp_shared);
    } else {
      tr_debug("tr_tids_req_handler: route not local.");
      aaa_servers = tr_aaa_server_new(tmp_ctx, trp_route_get_next_hop(route));
      idp_shared = 0;
    }

    /* Since we aren't defaulting, check idp coi and apc membership */
    if (NULL == (tr_comm_find_idp(cfg_mgr->active->ctable, cfg_comm, fwd_req->realm))) {
      tr_notice("tr_tids_req_handler: IDP Realm (%s) not member of community (%s).", orig_req->realm->buf, orig_req->comm->buf);
      tid_resp_set_err_msg(resp, tr_new_name("IDP community membership error"));
      retval=-1;
      goto cleanup;
    }
    if ( cfg_apc && (NULL == (tr_comm_find_idp(cfg_mgr->active->ctable, cfg_apc, fwd_req->realm)))) {
      tr_notice("tr_tids_req_handler: IDP Realm (%s) not member of APC (%s).", orig_req->realm->buf, orig_req->comm->buf);
      tid_resp_set_err_msg(resp, tr_new_name("IDP APC membership error"));
      retval=-1;
      goto cleanup;
    }
  }

  /* Make sure we came through with a AAA server. If not, we can't handle the request. */
  if (NULL == aaa_servers) {
    tr_notice("tr_tids_req_handler: no route or AAA server for realm (%s) in community (%s).",
              orig_req->realm->buf, orig_req->comm->buf);
    tid_resp_set_err_msg(resp, tr_new_name("Missing trust route error"));
    retval = -1;
    goto cleanup;
  }

  /* send a TID request to the AAA server(s), and get the answer(s) */
  tr_debug("tr_tids_req_handler: sending TID request(s).");
  if (cfg_apc)
    expiration_interval = cfg_apc->expiration_interval;
  else expiration_interval = cfg_comm->expiration_interval;
  if (fwd_req->expiration_interval)
    fwd_req->expiration_interval =  (expiration_interval < fwd_req->expiration_interval) ? expiration_interval : fwd_req->expiration_interval;
  else fwd_req->expiration_interval = expiration_interval;

  /* Set up message queue for replies from req forwarding threads */
  mq=tr_mq_new(tmp_ctx);
  if (mq==NULL) {
    tr_notice("tr_tids_req_handler: unable to allocate message queue.");
    retval=-1;
    goto cleanup;
  }
  tr_debug("tr_tids_req_handler: message queue allocated.");

  /* start threads */
  aaa_iter=tr_aaa_server_iter_new(tmp_ctx);
  if (aaa_iter==NULL) {
    tr_notice("tr_tids_req_handler: unable to allocate AAA server iterator.");
    retval=-1;
    goto cleanup;
  }
  for (n_aaa=0, this_aaa=tr_aaa_server_iter_first(aaa_iter, aaa_servers);
       this_aaa!=NULL;
       n_aaa++, this_aaa=tr_aaa_server_iter_next(aaa_iter)) {
    tr_debug("tr_tids_req_handler: Preparing to start thread %d.", n_aaa);

    aaa_cookie[n_aaa]=talloc(tmp_ctx, struct tr_tids_fwd_cookie);
    if (aaa_cookie[n_aaa]==NULL) {
      tr_notice("tr_tids_req_handler: unable to allocate cookie for AAA thread %d.", n_aaa);
      retval=-1;
      goto cleanup;
    }
    talloc_set_destructor((void *)(aaa_cookie[n_aaa]), tr_tids_fwd_cookie_destructor);
    /* fill in the cookie. To ensure the thread has valid data even if we exit first and
     * abandon it, duplicate anything pointed to (except the mq). */
    aaa_cookie[n_aaa]->thread_id=n_aaa;
    if (0!=pthread_mutex_init(&(aaa_cookie[n_aaa]->mutex), NULL)) {
      tr_notice("tr_tids_req_handler: unable to init mutex for AAA thread %d.", n_aaa);
      retval=-1;
      goto cleanup;
    }
    aaa_cookie[n_aaa]->mq=mq;
    aaa_cookie[n_aaa]->aaa_hostname=tr_dup_name(this_aaa->hostname);
    aaa_cookie[n_aaa]->dh_params=tr_dh_dup(orig_req->tidc_dh);
    aaa_cookie[n_aaa]->fwd_req=tid_dup_req(fwd_req);
    talloc_steal(aaa_cookie[n_aaa], aaa_cookie[n_aaa]->fwd_req);
    tr_debug("tr_tids_req_handler: cookie %d initialized.", n_aaa);

    /* Take the cookie out of tmp_ctx before starting thread. If thread starts, it becomes
     * responsible for freeing it until it queues a response. If we did not do this, the possibility
     * exists that this function exits, freeing the cookie, before the thread takes the cookie
     * out of our tmp_ctx. This would cause a segfault or talloc error in the thread. */
    talloc_steal(NULL, aaa_cookie[n_aaa]);
    if (0!=pthread_create(&(aaa_thread[n_aaa]), NULL, tr_tids_req_fwd_thread, aaa_cookie[n_aaa])) {
      talloc_steal(tmp_ctx, aaa_cookie[n_aaa]); /* thread start failed; steal this back */
      tr_notice("tr_tids_req_handler: unable to start AAA thread %d.", n_aaa);
      retval=-1;
      goto cleanup;
    }
    tr_debug("tr_tids_req_handler: thread %d started.", n_aaa);
  }

  /* determine expiration time */
  if (0!=tr_mq_pop_timeout(cfg_mgr->active->internal->tid_req_timeout, &ts_abort)) {
    tr_notice("tr_tids_req_handler: unable to read clock for timeout.");
    retval=-1;
    goto cleanup;
  }

  /* wait for responses */
  tr_debug("tr_tids_req_handler: waiting for response(s).");
  n_responses=0;
  n_failed=0;
  while (((n_responses+n_failed)<n_aaa) &&
         (NULL!=(msg=tr_mq_pop(mq, &ts_abort)))) {
    /* process message */
    if (0==strcmp(tr_mq_msg_get_message(msg), TR_TID_MQMSG_SUCCESS)) {
      payload=talloc_get_type_abort(tr_mq_msg_get_payload(msg), TR_RESP_COOKIE);
      talloc_steal(tmp_ctx, payload); /* put this back in our context */
      aaa_resp[payload->thread_id]=payload->resp; /* save pointers to these */

      if (payload->resp->result==TID_SUCCESS) {
        tr_tids_merge_resps(resp, payload->resp);
        n_responses++;
      } else {
        n_failed++;
        tr_notice("tr_tids_req_handler: TID error received from AAA server %d: %.*s",
                  payload->thread_id,
                  payload->resp->err_msg->len,
                  payload->resp->err_msg->buf);
      }
    } else if (0==strcmp(tr_mq_msg_get_message(msg), TR_TID_MQMSG_FAILURE)) {
      /* failure */
      n_failed++;
      payload=talloc_get_type(tr_mq_msg_get_payload(msg), TR_RESP_COOKIE);
      if (payload!=NULL) 
        talloc_steal(tmp_ctx, payload); /* put this back in our context */
      else {
        /* this means the thread was unable to allocate a response cookie, and we thus cannot determine which thread it was. This is bad and should never happen in a working system.. Give up. */
        tr_notice("tr_tids_req_handler: TID request thread sent invalid reply. Aborting!");
        retval=-1;
        goto cleanup;
      }
      tr_notice("tr_tids_req_handler: TID request for AAA server %d failed.",
                payload->thread_id);
    } else {
      /* unexpected message */
      tr_err("tr_tids_req_handler: Unexpected message received. Aborting!");
      retval=-1;
      goto cleanup;
    }
    
    /* Set the cookie pointer to NULL so we know we've dealt with this one. The
     * cookie itself is in our tmp_ctx, which we'll free before exiting. Let it hang
     * around in case we are still using pointers to elements of the cookie. */
    aaa_cookie[payload->thread_id]=NULL;

    tr_mq_msg_free(msg);

    /* check whether we've received enough responses to exit */
    if ((idp_shared && (n_responses>0)) ||
        (resp_frac_denom*n_responses>=resp_frac_numer*n_aaa))
      break;
  }

  tr_debug("tr_tids_req_handler: done waiting for responses. %d responses, %d failures.",
           n_responses, n_failed);
  /* Inform any remaining threads that we will no longer handle their responses. */
  for (ii=0; ii<n_aaa; ii++) {
    if (aaa_cookie[ii]!=NULL) {
      if (0!=tr_tids_fwd_get_mutex(aaa_cookie[ii]))
        tr_notice("tr_tids_req_handler: unable to get mutex for AAA thread %d.", ii);

      aaa_cookie[ii]->mq=NULL; /* threads will not try to respond through a null mq */

      if (0!=tr_tids_fwd_release_mutex(aaa_cookie[ii]))
        tr_notice("tr_tids_req_handler: unable to release mutex for AAA thread %d.", ii);
    }
  }

  /* Now all threads have either replied (and aaa_cookie[ii] is null) or have been told not to
   * reply (by setting their mq pointer to null). However, some may have responded by placing
   * a message on the mq after we last checked but before we set their mq pointer to null. These
   * will not know that we gave up on them, so we must free their cookies for them. We can just
   * go through any remaining messages on the mq to identify these threads. By putting them in
   * our context instead of freeing them directly, we ensure we don't accidentally invalidate
   * any of our own pointers into the structure before this function exits. */
  while (NULL!=(msg=tr_mq_pop(mq, NULL))) {
    payload=(TR_RESP_COOKIE *)tr_mq_msg_get_payload(msg);
    if (aaa_cookie[payload->thread_id]!=NULL)
      talloc_steal(tmp_ctx, aaa_cookie[payload->thread_id]);

    tr_mq_msg_free(msg);
  }

  if (n_responses==0) {
    /* No requests succeeded, so this will be an error */
    retval = -1;

    /* If we got any error responses, send an arbitrarily chosen one. */
    for (ii=0; ii<n_aaa; ii++) {
      if (aaa_resp[ii] != NULL) {
        tid_resp_cpy(resp, aaa_resp[ii]);
        goto cleanup;
      }
    }
    /* No error responses at all, so generate our own error. */
    tid_resp_set_err_msg(resp, tr_new_name("Unable to contact AAA server(s)."));
    goto cleanup;
  }

  /* success! */
  retval=0;
    
cleanup:
  talloc_free(tmp_ctx);
  return retval;
}

static int tr_tids_gss_handler(gss_name_t client_name, TR_NAME *gss_name,
                               void *data)
{
  struct tr_tids_event_cookie *cookie=talloc_get_type_abort(data, struct tr_tids_event_cookie);
  TIDS_INSTANCE *tids = cookie->tids;
  TR_CFG_MGR *cfg_mgr = cookie->cfg_mgr;

  if ((!client_name) || (!gss_name) || (!tids) || (!cfg_mgr)) {
    tr_debug("tr_tidc_gss_handler: Bad parameters.");
    return -1;
  }

  /* Ensure at least one client exists using this GSS name */
  if (NULL == tr_rp_client_lookup(cfg_mgr->active->rp_clients, gss_name)) {
    tr_debug("tr_tids_gss_handler: Unknown GSS name %.*s", gss_name->len, gss_name->buf);
    return -1;
  }

  /* Store the GSS name */
  tids->gss_name = tr_dup_name(gss_name);
  tr_debug("Client's GSS Name: %.*s", gss_name->len, gss_name->buf);

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
                       TRPS_INSTANCE *trps,
                       struct tr_socket_event *tids_ev)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_tids_event_cookie *cookie=NULL;
  int retval=0;
  int ii=0;

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
  cookie->trps=trps;
  talloc_steal(tids, cookie);

  /* get a tids listener */
  tids_ev->n_sock_fd = (int)tids_get_listener(tids,
                                              tr_tids_req_handler,
                                              tr_tids_gss_handler,
                                              cfg_mgr->active->internal->hostname,
                                              cfg_mgr->active->internal->tids_port,
                                              (void *)cookie,
                                              tids_ev->sock_fd,
                                              TR_MAX_SOCKETS);
  if (tids_ev->n_sock_fd==0) {
    tr_crit("Error opening TID server socket.");
    retval=1;
    goto cleanup;
  }

  /* Set up events */
  for (ii=0; ii<tids_ev->n_sock_fd; ii++) {
    tids_ev->ev[ii]=event_new(base,
                              tids_ev->sock_fd[ii],
                              EV_READ|EV_PERSIST,
                              tr_tids_event_cb,
                              (void *)tids);
    event_add(tids_ev->ev[ii], NULL);
  }

cleanup:
  talloc_free(tmp_ctx);
  return retval;
}
