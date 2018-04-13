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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <jansson.h>
#include <talloc.h>
#include <poll.h>
#include <tid_internal.h>
#include <gsscon.h>
#include <tr_debug.h>
#include <tr_msg.h>
#include <tr_socket.h>
#include <tr_gss.h>
#include <tr_event.h>

static TID_RESP *tids_create_response(TALLOC_CTX *mem_ctx, TIDS_INSTANCE *tids, TID_REQ *req)
{
  TID_RESP *resp=NULL;
  int success=0;

  if (NULL == (resp = tid_resp_new(mem_ctx))) {
    tr_crit("tids_create_response: Error allocating response structure.");
    return NULL;
  }
  
  resp->result = TID_SUCCESS; /* presume success */
  if ((NULL == (resp->rp_realm = tr_dup_name(req->rp_realm))) ||
      (NULL == (resp->realm = tr_dup_name(req->realm))) ||
      (NULL == (resp->comm = tr_dup_name(req->comm)))) {
    tr_crit("tids_create_response: Error allocating fields in response.");
    goto cleanup;
  }
  if (req->orig_coi) {
    if (NULL == (resp->orig_coi = tr_dup_name(req->orig_coi))) {
      tr_crit("tids_create_response: Error allocating fields in response.");
      goto cleanup;
    }
  }

  success=1;

cleanup:
  if ((!success) && (resp!=NULL)) {
    talloc_free(resp);
    resp=NULL;
  }
  return resp;
}

static int tids_handle_request(TIDS_INSTANCE *tids, TID_REQ *req, TID_RESP *resp)
{
  int rc=-1;

  /* Check that this is a valid TID Request.  If not, send an error return. */
  if ((!req) ||
      (!(req->rp_realm)) ||
      (!(req->realm)) ||
      (!(req->comm))) {
    tr_notice("tids_handle_request(): Not a valid TID Request.");
    resp->result = TID_ERROR;
    resp->err_msg = tr_new_name("Bad request format");
    return -1;
  }

  tr_debug("tids_handle_request: adding self to req path.");
  tid_req_add_path(req, tids->hostname, tids->tids_port);
  
  /* Call the caller's request handler */
  /* TBD -- Handle different error returns/msgs */
  if (0 > (rc = (*tids->req_handler)(tids, req, resp, tids->cookie))) {
    /* set-up an error response */
    tr_debug("tids_handle_request: req_handler returned error.");
    resp->result = TID_ERROR;
    if (!resp->err_msg)	/* Use msg set by handler, if any */
      resp->err_msg = tr_new_name("Internal processing error");
  }
  else {
    /* set-up a success response */
    tr_debug("tids_handle_request: req_handler returned success.");
    resp->result = TID_SUCCESS;
    resp->err_msg = NULL;	/* No error msg on successful return */
  }
    
  return rc;
}

/**
 * Produces a JSON-encoded msg containing the TID response
 *
 * @param mem_ctx talloc context for the return value
 * @param tids TIDS_INSTANCE handling the request
 * @param req incoming request
 * @param resp outgoing response
 * @return JSON-encoded message containing the TID response
 */
static char *tids_encode_response(TALLOC_CTX *mem_ctx, TIDS_INSTANCE *tids, TID_REQ *req, TID_RESP *resp)
{
  TR_MSG mresp;
  char *resp_buf = NULL;

  /* Construct the response message */
  mresp.msg_type = TID_RESPONSE;
  tr_msg_set_resp(&mresp, resp);

  /* Encode the message to JSON */
  resp_buf = tr_msg_encode(mem_ctx, &mresp);
  if (resp_buf == NULL) {
    tr_err("tids_encode_response: Error encoding json response.");
    return NULL;
  }
  tr_debug("tids_encode_response: Encoded response: %s", resp_buf);

  /* Success */
  return resp_buf;
}

/**
 * Encode/send an error response
 *
 * Part of the public interface
 *
 * @param tids
 * @param req
 * @param err_msg
 * @return
 */
int tids_send_err_response (TIDS_INSTANCE *tids, TID_REQ *req, const char *err_msg) {
  TID_RESP *resp = NULL;
  int rc = 0;

  if ((!tids) || (!req) || (!err_msg)) {
    tr_debug("tids_send_err_response: Invalid parameters.");
    return -1;
  }

  /* If we already sent a response, don't send another no matter what. */
  if (req->resp_sent)
    return 0;

  if (NULL == (resp = tids_create_response(req, tids, req))) {
    tr_crit("tids_send_err_response: Can't create response.");
    return -1;
  }

  /* mark this as an error response, and include the error message */
  resp->result = TID_ERROR;
  resp->err_msg = tr_new_name((char *)err_msg);
  resp->error_path = req->path;

  rc = tids_send_response(tids, req, resp);

  tid_resp_free(resp);
  return rc;
}

/**
 * Encode/send a response
 *
 * Part of the public interface
 *
 * @param tids
 * @param req
 * @param resp
 * @return
 */
int tids_send_response (TIDS_INSTANCE *tids, TID_REQ *req, TID_RESP *resp)
{
  int err;
  char *resp_buf;

  if ((!tids) || (!req) || (!resp)) {
    tr_debug("tids_send_response: Invalid parameters.");
    return -1;
  }

  /* Never send a second response if we already sent one. */
  if (req->resp_sent)
    return 0;

  resp_buf = tids_encode_response(NULL, tids, req, resp);
  if (resp_buf == NULL) {
    tr_err("tids_send_response: Error encoding json response.");
    tr_audit_req(req);
    return -1;
  }

  tr_debug("tids_send_response: Encoded response: %s", resp_buf);

  /* If external logging is enabled, fire off a message */
  /* TODO Can be moved to end once segfault in gsscon_write_encrypted_token fixed */
  tr_audit_resp(resp);

  /* Send the response over the connection */
  err = gsscon_write_encrypted_token (req->conn, req->gssctx, resp_buf,
                                            strlen(resp_buf) + 1);
  if (err) {
    tr_notice("tids_send_response: Error sending response over connection.");
    tr_audit_req(req);
    return -1;
  }

  /* indicate that a response has been sent for this request */
  req->resp_sent = 1;

  free(resp_buf);

  return 0;
}

/**
 * Callback to process a request and produce a response
 *
 * @param req_str JSON-encoded request
 * @param data pointer to a TIDS_INSTANCE
 * @return pointer to the response string or null to send no response
 */
static char *tids_req_cb(TALLOC_CTX *mem_ctx, const char *req_str, void *data)
{
  TIDS_INSTANCE *tids = talloc_get_type_abort(data, TIDS_INSTANCE);
  TR_MSG *mreq = NULL;
  TID_REQ *req = NULL;
  TID_RESP *resp = NULL;
  char *resp_str = NULL;
  int rc = 0;

  mreq = tr_msg_decode(req_str, strlen(req_str)); // allocates memory on success!
  if (mreq == NULL) {
    tr_debug("tids_req_cb: Error decoding request.");
    return NULL;
  }

  /* If this isn't a TID Request, just drop it. */
  if (mreq->msg_type != TID_REQUEST) {
    tr_msg_free_decoded(mreq);
    tr_debug("tids_req_cb: Not a TID request, dropped.");
    return NULL;
  }

  /* Get a handle on the request itself. Don't free req - it belongs to mreq */
  req = tr_msg_get_req(mreq);

  /* Allocate a response structure and populate common fields. The resp is in req's talloc context,
   * which will be cleaned up when mreq is freed. */
  resp = tids_create_response(req, tids, req);
  if (resp == NULL) {
    /* If we were unable to create a response, we cannot reply. Log an
     * error if we can, then drop the request. */
    tr_msg_free_decoded(mreq);
    tr_crit("tids_req_cb: Error creating response structure.");
    return NULL;
  }

  /* Handle the request and fill in resp */
  rc = tids_handle_request(tids, req, resp);
  if (rc < 0) {
    tr_debug("tids_req_cb: Error from tids_handle_request(), rc = %d.", rc);
    /* Fall through, to send the response, either way */
  }

  /* Convert the completed response into an encoded response */
  resp_str = tids_encode_response(mem_ctx, tids, req, resp);

  /* Finished; free the request and return */
  tr_msg_free_decoded(mreq); // this frees req and resp, too
  return resp_str;
}

TIDS_INSTANCE *tids_new(TALLOC_CTX *mem_ctx)
{
  return talloc_zero(mem_ctx, TIDS_INSTANCE);
}

/**
 * Create a new TIDS instance
 *
 * Deprecated: exists for ABI compatibility, but tids_new() should be used instead
 *
 */
TIDS_INSTANCE *tids_create(void)
{
  return talloc_zero(NULL, TIDS_INSTANCE);
}
/* Get a listener for tids requests, returns its socket fd. Accept
 * connections with tids_accept() */
nfds_t tids_get_listener(TIDS_INSTANCE *tids,
                         TIDS_REQ_FUNC *req_handler,
                         tids_auth_func *auth_handler,
                         const char *hostname,
                         unsigned int port,
                         void *cookie,
                         int *fd_out,
                         size_t max_fd)
{
  nfds_t n_fd = 0;
  nfds_t ii = 0;

  tids->tids_port = port;
  n_fd = tr_sock_listen_all(port, fd_out, max_fd);

  if (n_fd == 0)
    tr_err("tids_get_listener: Error opening port %d");
  else {
    /* opening port succeeded */
    tr_info("tids_get_listener: Opened port %d.", port);
    
    /* make this socket non-blocking */
    for (ii=0; ii<n_fd; ii++) {
      if (0 != fcntl(fd_out[ii], F_SETFL, O_NONBLOCK)) {
        tr_err("tids_get_listener: Error setting O_NONBLOCK.");
        for (ii=0; ii<n_fd; ii++) {
          close(fd_out[ii]);
          fd_out[ii]=-1;
        }
        n_fd = 0;
        break;
      }
    }
  }

  if (n_fd > 0) {
    /* store the caller's request handler & cookie */
    tids->req_handler = req_handler;
    tids->auth_handler = auth_handler;
    tids->hostname = hostname;
    tids->cookie = cookie;
  }

  return (int)n_fd;
}

/* Accept and process a connection on a port opened with tids_get_listener() */
int tids_accept(TIDS_INSTANCE *tids, int listen)
{
  int conn=-1;
  int pid=-1;

  if (0 > (conn = accept(listen, NULL, NULL))) {
    perror("Error from TIDS Server accept()");
    return 1;
  }

  if (0 > (pid = fork())) {
    perror("Error on fork()");
    return 1;
  }

  if (pid == 0) {
    close(listen);
    tr_gss_handle_connection(conn,
                             "trustidentity", tids->hostname, /* acceptor name */
                             tids->auth_handler, tids->cookie, /* auth callback and cookie */
                             tids_req_cb, tids /* req callback and cookie */
    );
    close(conn);
    exit(0); /* exit to kill forked child process */
  } else {
    close(conn);
  }

  /* clean up any processes that have completed  (TBD: move to main loop?) */
  while (waitpid(-1, 0, WNOHANG) > 0);

  return 0;
}

/* Process tids requests forever. Should not return except on error. */
int tids_start (TIDS_INSTANCE *tids,
                TIDS_REQ_FUNC *req_handler,
                tids_auth_func *auth_handler,
                const char *hostname,
                unsigned int port,
                void *cookie)
{
  int fd[TR_MAX_SOCKETS]={0};
  nfds_t n_fd=0;
  struct pollfd poll_fd[TR_MAX_SOCKETS]={{0}};
  int ii=0;

  n_fd = tids_get_listener(tids, req_handler, auth_handler, hostname, port, cookie, fd, TR_MAX_SOCKETS);
  if (n_fd <= 0) {
    perror ("Error from tids_listen()");
    return 1;
  }

  tr_info("Trust Path Query Server starting on host %s:%d.", hostname, port);

  /* set up the poll structs */
  for (ii=0; ii<n_fd; ii++) {
    poll_fd[ii].fd=fd[ii];
    poll_fd[ii].events=POLLIN;
  }

  while(1) {	/* accept incoming conns until we are stopped */
    /* clear out events from previous iteration */
    for (ii=0; ii<n_fd; ii++)
      poll_fd[ii].revents=0;

    /* wait indefinitely for a connection */
    if (poll(poll_fd, n_fd, -1) < 0) {
      perror("Error from poll()");
      return 1;
    }

    /* fork handlers for any sockets that have data */
    for (ii=0; ii<n_fd; ii++) {
      if (poll_fd[ii].revents == 0)
        continue;

      if ((poll_fd[ii].revents & POLLERR) || (poll_fd[ii].revents & POLLNVAL)) {
        perror("Error polling fd");
        continue;
      }

      if (poll_fd[ii].revents & POLLIN) {
        if (tids_accept(tids, poll_fd[ii].fd))
          tr_err("tids_start: error in tids_accept().");
      }
    }
  }

  return 1;	/* should never get here, loops "forever" */
}

void tids_destroy (TIDS_INSTANCE *tids)
{
  /* clean up logfiles */
  tr_log_close();

  if (tids)
    free(tids);
}
