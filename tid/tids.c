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

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <jansson.h>

#include <trust_router/tid.h>
#include <gsscon.h>
#include <tr_msg.h>

static TID_RESP *tids_create_response (TIDS_INSTANCE *tids, TID_REQ *req) 
{
  TID_RESP *resp;

  if ((NULL == (resp = calloc(sizeof(TID_RESP), 1)))) {
    fprintf(stderr, "tids_create_response: Error allocating response structure.\n");
    return NULL;
  }
  
  resp->result = TID_SUCCESS; /* presume success */
  if ((NULL == (resp->rp_realm = tr_dup_name(req->rp_realm))) ||
      (NULL == (resp->realm = tr_dup_name(req->realm))) ||
      (NULL == (resp->comm = tr_dup_name(req->comm)))) {
    fprintf(stderr, "tids_create_response: Error allocating fields in response.\n");
    return NULL;
  }
  if (req->orig_coi) {
    if (NULL == (resp->orig_coi = tr_dup_name(req->orig_coi))) {
      fprintf(stderr, "tids_create_response: Error allocating fields in response.\n");
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
    free (resp);
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
    
    fprintf (stdout, "tids_listen: TID Server listening on port %d\n", port);
    return conn; 
}

static int tids_auth_cb(gss_name_t clientName, gss_buffer_t displayName,
			void *data)
{
  struct tids_instance *inst = (struct tids_instance *) data;
  TR_NAME name ={(char *) displayName->value,
		 displayName->length};
  return inst->auth_handler(clientName, &name, inst->cookie);
}

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
    fprintf(stderr, "tids_auth_connection: Error from gsscon_passive_authenticate(), rc = %d.\n", rc);
    return -1;
  }

  if (rc = gsscon_authorize(*gssctx, &auth, &autherr)) {
    fprintf(stderr, "tids_auth_connection: Error from gsscon_authorize, rc = %d, autherr = %d.\n", 
	    rc, autherr);
    return -1;
  }

  if (auth)
    fprintf(stdout, "tids_auth_connection: Connection authenticated, conn = %d.\n", conn);
  else
    fprintf(stderr, "tids_auth_connection: Authentication failed, conn %d.\n", conn);

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

  fprintf(stdout, "tids_read_request():Request Received, %u bytes.\n", (unsigned) buflen);

  /* Parse request */
  if (NULL == ((*mreq) = tr_msg_decode(buf, buflen))) {
    fprintf(stderr, "tids_read_request():Error decoding request.\n");
    free (buf);
    return -1;
  }

  /* If this isn't a TID Request, just drop it. */
  if (TID_REQUEST != (*mreq)->msg_type) {
    fprintf(stderr, "tids_read_request(): Not a TID Request, dropped.\n");
    return -1;
  }

  free (buf);
  return buflen;
}

static int tids_handle_request (TIDS_INSTANCE *tids, TR_MSG *mreq, TID_RESP **resp) 
{
  int rc;

  /* Check that this is a valid TID Request.  If not, send an error return. */
  if ((!mreq->tid_req) ||
      (!mreq->tid_req->rp_realm) ||
      (!mreq->tid_req->realm) ||
      (!mreq->tid_req->comm)) {
    fprintf(stderr, "tids_handle_request():Not a valid TID Request.\n");
    (*resp)->result = TID_ERROR;
    (*resp)->err_msg = tr_new_name("Bad request format");
    return -1;
  }

  /* Call the caller's request handler */
  /* TBD -- Handle different error returns/msgs */
  if (0 > (rc = (*tids->req_handler)(tids, mreq->tid_req, &(*resp), tids->cookie))) {
    /* set-up an error response */
    (*resp)->result = TID_ERROR;
    if (!(*resp)->err_msg)	/* Use msg set by handler, if any */
      (*resp)->err_msg = tr_new_name("Internal processing error");
  }
  else {
    /* set-up a success response */
    (*resp)->result = TID_SUCCESS;
    (*resp)->err_msg = NULL;	/* No error msg on successful return */
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
    fprintf(stderr, "tids_send_err_response: Can't create response.\n");
    return -1;
  }

  /* mark this as an error response, and include the error message */
  resp->result = TID_ERROR;
  resp->err_msg = tr_new_name((char *)err_msg);

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
    fprintf (stderr, "tids_send_response: Invalid parameters.\n");

  /* Never send a second response if we already sent one. */
  if (req->resp_sent)
    return 0;

  mresp.msg_type = TID_RESPONSE;
  mresp.tid_resp = resp;
  
  if (NULL == (resp_buf = tr_msg_encode(&mresp))) {
    fprintf(stderr, "tids_send_response: Error encoding json response.\n");
    return -1;
  }

  fprintf(stderr, "tids_send_response: Encoded response:\n%s\n", resp_buf);
  
  /* Send the response over the connection */
  if (err = gsscon_write_encrypted_token (req->conn, req->gssctx, resp_buf, 
					  strlen(resp_buf) + 1)) {
    fprintf(stderr, "tids_send_response: Error sending response over connection.\n");
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
    fprintf(stderr, "tids_handle_connection: Error authorizing TID Server connection.\n");
    close(conn);
    return;
  }

  fprintf(stdout, "tids_handle_connection: Connection authorized!\n");

  while (1) {	/* continue until an error breaks us out */

    if (0 > (rc = tids_read_request(tids, conn, &gssctx, &mreq))) {
      fprintf(stderr, "tids_handle_connection: Error from tids_read_request(), rc = %d.\n", rc);
      return;
    } else if (0 == rc) {
      continue;
    }

    /* Put connection information into the request structure */
    mreq->tid_req->conn = conn;
    mreq->tid_req->gssctx = gssctx;

    /* Allocate a response structure and populate common fields */
    if (NULL == (resp = tids_create_response (tids, mreq->tid_req))) {
      fprintf(stderr, "tids_handle_connection: Error creating response structure.\n");
      /* try to send an error */
      tids_send_err_response(tids, mreq->tid_req, "Error creating response.\n");
      return;
    }

    if (0 > (rc = tids_handle_request(tids, mreq, &resp))) {
      fprintf(stderr, "tids_handle_connection: Error from tids_handle_request(), rc = %d.\n", rc);
      /* Fall through, to send the response, either way */
    }

    if (0 > (rc = tids_send_response(tids, mreq->tid_req, resp))) {
      fprintf(stderr, "tids_handle_connection: Error from tids_send_response(), rc = %d.\n", rc);
      /* if we didn't already send a response, try to send a generic error. */
      if (!mreq->tid_req->resp_sent)
	tids_send_err_response(tids, mreq->tid_req, "Error sending response.\n");
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

  if (0 > (listen = tids_listen(tids, port)))
    perror ("Error from tids_listen()");

  /* store the caller's request handler & cookie */
  tids->req_handler = req_handler;
  tids->auth_handler = auth_handler;
  tids->hostname = hostname;
  tids->cookie = cookie;

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
      return 0;
    } else {
      close(conn);
    }
  }

  return 1;	/* should never get here */
}

void tids_destroy (TIDS_INSTANCE *tids)
{
  if (tids)
    free(tids);
}


