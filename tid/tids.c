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

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <jansson.h>
#include <talloc.h>
#include <tid_internal.h>
#include <gsscon.h>
#include <tr_debug.h>
#include <tr_msg.h>

static TID_RESP *tids_create_response (TIDS_INSTANCE *tids, TID_REQ *req) 
{
  TID_RESP *resp;

  if ((NULL == (resp = talloc_zero(req, TID_RESP)))) {
    tr_crit("tids_create_response: Error allocating response structure.");
    return NULL;
  }
  
  resp->result = TID_SUCCESS; /* presume success */
  if ((NULL == (resp->rp_realm = tr_dup_name(req->rp_realm))) ||
      (NULL == (resp->realm = tr_dup_name(req->realm))) ||
      (NULL == (resp->comm = tr_dup_name(req->comm)))) {
    tr_crit("tids_create_response: Error allocating fields in response.");
    return NULL;
  }
  if (req->orig_coi) {
    if (NULL == (resp->orig_coi = tr_dup_name(req->orig_coi))) {
      tr_crit("tids_create_response: Error allocating fields in response.");
      return NULL;
    }
  }
  return resp;
}

static void tids_destroy_response(TIDS_INSTANCE *tids, TID_RESP *resp) 
{
  if (resp) {
    if (resp->err_msg)
      tr_free_name(resp->err_msg);
    if (resp->rp_realm)
      tr_free_name(resp->rp_realm);
    if (resp->realm)
      tr_free_name(resp->realm);
    if (resp->comm)
      tr_free_name(resp->comm);
    if (resp->orig_coi)
      tr_free_name(resp->orig_coi);
    talloc_free(resp);
  }
}

static int tids_listen (TIDS_INSTANCE *tids, int port) 
{
    int rc = 0;
    int conn = -1;
    int optval = 1;

    union {
      struct sockaddr_storage storage;
      struct sockaddr_in in4;
    } addr;

    struct sockaddr_in *saddr = (struct sockaddr_in *) &addr.in4;

    saddr->sin_port = htons (port);
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = INADDR_ANY;

    if (0 > (conn = socket (AF_INET, SOCK_STREAM, 0)))
      return conn;

    setsockopt(conn, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (0 > (rc = bind (conn, (struct sockaddr *) saddr, sizeof(struct sockaddr_in))))
      return rc;

    if (0 > (rc = listen(conn, 512)))
      return rc;

    tr_debug("tids_listen: TID Server listening on port %d", port);
    return conn;
}

/* returns EACCES if authorization is denied */
static int tids_auth_cb(gss_name_t clientName, gss_buffer_t displayName,
			void *data)
{
  struct tids_instance *inst = (struct tids_instance *) data;
  TR_NAME name ={(char *) displayName->value,
		 displayName->length};
  int result=0;

  if (0!=inst->auth_handler(clientName, &name, inst->cookie)) {
    tr_debug("tids_auth_cb: client '%.*s' denied authorization.", name.len, name.buf);
    result=EACCES; /* denied */
  }

  return result;
}

/* returns 0 on authorization success, 1 on failure, or -1 in case of error */
static int tids_auth_connection (struct tids_instance *inst,
				 int conn, gss_ctx_id_t *gssctx)
{
  int rc = 0;
  int auth, autherr = 0;
  gss_buffer_desc nameBuffer = {0, NULL};
  char *name = 0;
  int nameLen = 0;

  nameLen = asprintf(&name, "trustidentity@%s", inst->hostname);
  nameBuffer.length = nameLen;
  nameBuffer.value = name;
  
  if (rc = gsscon_passive_authenticate(conn, nameBuffer, gssctx, tids_auth_cb, inst)) {
    tr_debug("tids_auth_connection: Error from gsscon_passive_authenticate(), rc = %d.", rc);
    return -1;
  }

  if (rc = gsscon_authorize(*gssctx, &auth, &autherr)) {
    tr_debug("tids_auth_connection: Error from gsscon_authorize, rc = %d, autherr = %d.", 
	    rc, autherr);
    return -1;
  }

  if (auth)
    tr_debug("tids_auth_connection: Connection authenticated, conn = %d.", conn);
  else
    tr_debug("tids_auth_connection: Authentication failed, conn %d.", conn);

  return !auth;
}

static int tids_read_request (TIDS_INSTANCE *tids, int conn, gss_ctx_id_t *gssctx, TR_MSG **mreq)
{
  int err;
  char *buf;
  size_t buflen = 0;

  if (err = gsscon_read_encrypted_token(conn, *gssctx, &buf, &buflen)) {
    if (buf)
      free(buf);
    return -1;
  }

  tr_debug("tids_read_request():Request Received, %u bytes.", (unsigned) buflen);

  /* Parse request */
  if (NULL == ((*mreq) = tr_msg_decode(buf, buflen))) {
    tr_debug("tids_read_request():Error decoding request.");
    free (buf);
    return -1;
  }

  /* If this isn't a TID Request, just drop it. */
  if (TID_REQUEST != (*mreq)->msg_type) {
    tr_debug("tids_read_request(): Not a TID Request, dropped.");
    return -1;
  }

  free (buf);
  return buflen;
}

static int tids_handle_request (TIDS_INSTANCE *tids, TR_MSG *mreq, TID_RESP *resp) 
{
  int rc;

  /* Check that this is a valid TID Request.  If not, send an error return. */
  if ((!tr_msg_get_req(mreq)) ||
      (!tr_msg_get_req(mreq)->rp_realm) ||
      (!tr_msg_get_req(mreq)->realm) ||
      (!tr_msg_get_req(mreq)->comm)) {
    tr_notice("tids_handle_request(): Not a valid TID Request.");
    resp->result = TID_ERROR;
    resp->err_msg = tr_new_name("Bad request format");
    return -1;
  }

  tid_req_add_path(tr_msg_get_req(mreq), tids->hostname, tids->tids_port);
  
  /* Call the caller's request handler */
  /* TBD -- Handle different error returns/msgs */
  if (0 > (rc = (*tids->req_handler)(tids, tr_msg_get_req(mreq), resp, tids->cookie))) {
    /* set-up an error response */
    resp->result = TID_ERROR;
    if (!resp->err_msg)	/* Use msg set by handler, if any */
      resp->err_msg = tr_new_name("Internal processing error");
  }
  else {
    /* set-up a success response */
    resp->result = TID_SUCCESS;
    resp->err_msg = NULL;	/* No error msg on successful return */
  }
    
  return rc;
}

int tids_send_err_response (TIDS_INSTANCE *tids, TID_REQ *req, const char *err_msg) {
  TID_RESP *resp = NULL;
  int rc = 0;

  /* If we already sent a response, don't send another no matter what. */
  if (req->resp_sent)
    return 0;

  if (NULL == (resp = tids_create_response(tids, req))) {
    tr_crit("tids_send_err_response: Can't create response.");
    return -1;
  }

  
  /* mark this as an error response, and include the error message */
  resp->result = TID_ERROR;
  resp->err_msg = tr_new_name((char *)err_msg);
  resp->error_path = req->path;

  rc = tids_send_response(tids, req, resp);
  
  tids_destroy_response(tids, resp);
  return rc;
}

int tids_send_response (TIDS_INSTANCE *tids, TID_REQ *req, TID_RESP *resp)
{
  int err;
  TR_MSG mresp;
  char *resp_buf;

  if ((!tids) || (!req) || (!resp))
    tr_debug("tids_send_response: Invalid parameters.");

  /* Never send a second response if we already sent one. */
  if (req->resp_sent)
    return 0;

  mresp.msg_type = TID_RESPONSE;
  tr_msg_set_resp(&mresp, resp);

  if (NULL == (resp_buf = tr_msg_encode(&mresp))) {

    fprintf(stderr, "tids_send_response: Error encoding json response.\n");
    tr_audit_req(req);

    return -1;
  }

  tr_debug("tids_send_response: Encoded response: %s", resp_buf);

  /* If external logging is enabled, fire off a message */
  /* TODO Can be moved to end once segfault in gsscon_write_encrypted_token fixed */
  tr_audit_resp(resp);

  /* Send the response over the connection */
  if (err = gsscon_write_encrypted_token (req->conn, req->gssctx, resp_buf, 
					  strlen(resp_buf) + 1)) {
    tr_notice("tids_send_response: Error sending response over connection.");

    tr_audit_req(req);

    return -1;
  }

  /* indicate that a response has been sent for this request */
  req->resp_sent = 1;

  free(resp_buf);

  return 0;
}

static void tids_handle_connection (TIDS_INSTANCE *tids, int conn)
{
  TR_MSG *mreq = NULL;
  TID_RESP *resp = NULL;
  int rc = 0;
  gss_ctx_id_t gssctx = GSS_C_NO_CONTEXT;

  if (tids_auth_connection(tids, conn, &gssctx)) {
    tr_notice("tids_handle_connection: Error authorizing TID Server connection.");
    close(conn);
    return;
  }

  tr_debug("tids_handle_connection: Connection authorized!");

  while (1) {	/* continue until an error breaks us out */

    if (0 > (rc = tids_read_request(tids, conn, &gssctx, &mreq))) {
      tr_debug("tids_handle_connection: Error from tids_read_request(), rc = %d.", rc);
      return;
    } else if (0 == rc) {
      continue;
    }

    /* Put connection information into the request structure */
    tr_msg_get_req(mreq)->conn = conn;
    tr_msg_get_req(mreq)->gssctx = gssctx;

    /* Allocate a response structure and populate common fields */
    if (NULL == (resp = tids_create_response (tids, tr_msg_get_req(mreq)))) {
      tr_crit("tids_handle_connection: Error creating response structure.");
      /* try to send an error */
      tids_send_err_response(tids, tr_msg_get_req(mreq), "Error creating response.");
      return;
    }

    if (0 > (rc = tids_handle_request(tids, mreq, resp))) {
      tr_debug("tids_handle_connection: Error from tids_handle_request(), rc = %d.", rc);
      /* Fall through, to send the response, either way */
    }

    if (0 > (rc = tids_send_response(tids, tr_msg_get_req(mreq), resp))) {
      tr_debug("tids_handle_connection: Error from tids_send_response(), rc = %d.", rc);
      /* if we didn't already send a response, try to send a generic error. */
      if (!tr_msg_get_req(mreq)->resp_sent)
	tids_send_err_response(tids, tr_msg_get_req(mreq), "Error sending response.");
      /* Fall through to free the response, either way. */
    }
    
    tids_destroy_response(tids, resp);
    return;
  } 
}

TIDS_INSTANCE *tids_create (void)
{
  TIDS_INSTANCE *tids = NULL;
  if (tids = malloc(sizeof(TIDS_INSTANCE)))
    memset(tids, 0, sizeof(TIDS_INSTANCE));
  return tids;
}

/* Get a listener for tids requests, returns its socket fd. Accept
 * connections with tids_accept() */
int tids_get_listener(TIDS_INSTANCE *tids, 
                      TIDS_REQ_FUNC *req_handler,
                      tids_auth_func *auth_handler,
                      const char *hostname,
                      unsigned int port,
                      void *cookie)
{
  int listen = -1;

  tids->tids_port = port;
  if (0 > (listen = tids_listen(tids, port))) {
    char errbuf[256];
    if (0 == strerror_r(errno, errbuf, 256)) {
      tr_debug("tids_get_listener: Error opening port %d: %s.", port, errbuf);
    } else {
      tr_debug("tids_get_listener: Unknown error openining port %d.", port);
    }
  } 

  if (listen > 0) {
    /* opening port succeeded */
    tr_debug("tids_get_listener: Opened port %d.", port);
    
    /* make this socket non-blocking */
    if (0 != fcntl(listen, F_SETFD, O_NONBLOCK)) {
      tr_debug("tids_get_listener: Error setting O_NONBLOCK.");
      close(listen);
      listen=-1;
    }
  }

  if (listen > 0) {
    /* store the caller's request handler & cookie */
    tids->req_handler = req_handler;
    tids->auth_handler = auth_handler;
    tids->hostname = hostname;
    tids->cookie = cookie;
  }

  return listen;
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
    tids_handle_connection(tids, conn);
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
  int listen = -1;
  int conn = -1;
  pid_t pid;

  tids->tids_port = port;
  if (0 > (listen = tids_listen(tids, port)))
    perror ("Error from tids_listen()");

  /* store the caller's request handler & cookie */
  tids->req_handler = req_handler;
  tids->auth_handler = auth_handler;
  tids->hostname = hostname;
  tids->cookie = cookie;

  tr_info("Trust Path Query Server starting on host %s:%d.", hostname, port);

  while(1) {	/* accept incoming conns until we are stopped */

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
      tids_handle_connection(tids, conn);
      close(conn);
      exit(0); /* exit to kill forked child process */
    } else {
      close(conn);
    }

    /* clean up any processes that have completed */
    while (waitpid(-1, 0, WNOHANG) > 0);
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
