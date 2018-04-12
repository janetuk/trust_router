/*
 * Copyright (c) 2018, JANET(UK)
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

#include <tr_config.h>
#include <tr_debug.h>
#include <mon_internal.h>

/*
 * Cookie for the event handling callback
 */
struct tr_mons_event_cookie {
  MONS_INSTANCE *mons;
  TR_CFG_MGR *cfg_mgr;
};


/**
 * Callback to handle a triggered event
 *
 * @param listener file descriptor of the socket that triggered the event
 * @param event libevent2 event
 * @param arg pointer to our MONS_INSTANCE
 */
static void tr_mons_event_cb(int listener, short event, void *arg)
{
  MONS_INSTANCE *mons = talloc_get_type_abort(arg, MONS_INSTANCE);

  // check that we were not accidentally triggered
  if (0==(event & EV_READ))
    tr_debug("tr_mons_event_cb: unexpected event on monitoring interface socket (event=0x%X)", event);
  else
    mons_accept(mons, listener);
}


/**
 * Callback to handle an incoming monitoring request
 *
 * @param mons monitoring interface instance
 * @param orig_req incoming request
 * @param resp destination for outgoing response
 * @param cookie_in cookie from the event handling system
 * @return 0 on success
 */
static int tr_mons_req_handler(MONS_INSTANCE *mons,
                               MON_REQ *orig_req,
                               MON_RESP *resp,
                               void *cookie_in)
{
  return -1;
}

/**
 * Callback to authorize a GSS client
 *
 * @param client_name ?
 * @param gss_name GSS name of credential attempting to authorize
 * @param cookie_in event cookie
 * @return 0 if authorization is successful, -1 if not
 */
static int tr_mons_auth_handler(gss_name_t client_name, TR_NAME *gss_name, void *cookie_in)
{
  struct tr_mons_event_cookie *cookie=talloc_get_type_abort(cookie_in, struct tr_mons_event_cookie);
  MONS_INSTANCE *mons = cookie->mons;
  TR_CFG_MGR *cfg_mgr = cookie->cfg_mgr;

  if ((!client_name) || (!gss_name) || (!mons) || (!cfg_mgr)) {
    tr_debug("tr_mons_gss_handler: Bad parameters.");
    return -1;
  }

  /* Ensure at least one client exists using this GSS name */
  if (! tr_gss_names_matches(mons->authorized_gss_names, gss_name)) {
    tr_info("tr_mons_gss_handler: Unauthorized request from %.*s", gss_name->len, gss_name->buf);
    return -1;
  }

  /* Credential was valid, authorize it */
  tr_info("tr_mons_gss_handler: Authorized request from %.*s", gss_name->len, gss_name->buf);
  return 0;
}


/*
 *
 * Get a listener for monitoring requests, returns its socket fd. Accept
 * connections with tids_accept() */

/**
 * Configure the monitoring service instance and set up its event handler
 *
 * @param base libevent2 event base
 * @param mons MONS_INSTANCE for this monitoring interface
 * @param cfg_mgr configuration manager instance
 * @param mons_ev monitoring interface event instance
 * @return 0 on success, nonzero on failure.
 * */
int tr_mon_event_init(struct event_base *base, MONS_INSTANCE *mons, TR_CFG_MGR *cfg_mgr, struct tr_socket_event *mons_ev)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_mons_event_cookie *cookie=NULL;
  int retval=0;
  int ii=0;

  if (mons_ev == NULL) {
    tr_debug("tr_mon_event_init: Null mons_ev.");
    retval=1;
    goto cleanup;
  }

  /* Create the cookie for callbacks. We'll put it in the mons context, so it will
   * be cleaned up when mons is freed by talloc_free. */
  cookie=talloc(tmp_ctx, struct tr_mons_event_cookie);
  if (cookie == NULL) {
    tr_debug("tr_mons_event_init: Unable to allocate cookie.");
    retval=1;
    goto cleanup;
  }
  cookie->mons=mons;
  cookie->cfg_mgr=cfg_mgr;
  talloc_steal(mons, cookie);

  /* get a monitoring interface listener */
  mons_ev->n_sock_fd = mons_get_listener(mons,
                                         tr_mons_req_handler,
                                         tr_mons_auth_handler,
                                         cfg_mgr->active->internal->monitoring_port,
                                         (void *)cookie,
                                         mons_ev->sock_fd,
                                         TR_MAX_SOCKETS);
  if (mons_ev->n_sock_fd==0) {
    tr_crit("Error opening monitoring interface socket.");
    retval=1;
    goto cleanup;
  }

  /* Set up events */
  for (ii=0; ii<mons_ev->n_sock_fd; ii++) {
    mons_ev->ev[ii]=event_new(base,
                              mons_ev->sock_fd[ii],
                              EV_READ|EV_PERSIST,
                              tr_mons_event_cb,
                              (void *)mons);
    event_add(mons_ev->ev[ii], NULL);
  }

cleanup:
  talloc_free(tmp_ctx);
  return retval;
}
