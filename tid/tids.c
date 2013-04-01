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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <jansson.h>

#include <gsscon.h>
#include <tr_msg.h>
#include <trust_router/tid.h>

static int tids_listen (TIDS_INSTANCE *tids, int port) 
{
    int rc = 0;
    int conn = -1;
    struct sockaddr_storage addr;
    struct sockaddr_in *saddr = (struct sockaddr_in *) &addr;
    
    saddr->sin_port = htons (port);
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = INADDR_ANY;

    if (0 > (conn = socket (AF_INET, SOCK_STREAM, 0)))
      return conn;
        
    if (0 > (rc = bind (conn, (struct sockaddr *) saddr, sizeof(struct sockaddr_in))))
      return rc;
        
    if (0 > (rc = listen(conn, 512)))
      return rc;
    
    fprintf (stdout, "TID Server listening on port %d\n", port);
    return conn; 
}

static int tids_auth_connection (int conn, gss_ctx_id_t *gssctx)
{
  int rc = 0;
  int auth, autherr = 0;

  if (rc = gsscon_passive_authenticate(conn, gssctx)) {
    fprintf(stderr, "Error from gsscon_passive_authenticate(), rc = %d.\n", rc);
    return -1;
  }

  if (rc = gsscon_authorize(*gssctx, &auth, &autherr)) {
    fprintf(stderr, "Error from gsscon_authorize, rc = %d, autherr = %d.\n", 
	    rc, autherr);
    return -1;
  }

  if (auth)
    fprintf(stdout, "Connection authenticated, conn = %d.\n", conn);
  else
    fprintf(stderr, "Authentication failed, conn %d.\n", conn);

  return auth;
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

  fprintf(stdout, "tids_read_request():Request Received, %d bytes.\n", buflen);

  /* Parse request */
  if (NULL == ((*mreq) = tr_msg_decode(buf, buflen))) {
    printf("tids_read_request():Error decoding request.\n");
    free (buf);
    return -1;
  }

  /* If this isn't a TID Request, just drop it. */
  if (TID_REQUEST != (*mreq)->msg_type) {
    printf("tids_read_request(): Not a TID Request, dropped.\n");
    return -1;
  }

  free (buf);
  return buflen;
}

static int tids_handle_request (TIDS_INSTANCE *tids, TR_MSG *mreq, TR_MSG **mresp) 
{
  int rc;
  TID_RESP *resp;

  /* Check that this is a valid TID Request.  If not, send an error return. */
  if ((!mreq->tid_req) ||
      (!mreq->tid_req->rp_realm) ||
      (!mreq->tid_req->realm) ||
      (!mreq->tid_req->comm)) {
    printf("tids_handle_request():Not a valid TID Request.\n");
    (*mresp)->tid_resp->result = TID_ERROR;
    (*mresp)->tid_resp->err_msg = tr_new_name("Bad request format");
    return -1;
  }

  /* Call the caller's request handler */
  /* TBD -- Handle different error returns/msgs */
  resp = (*mresp)->tid_resp;
  if (0 > (rc = (*tids->req_handler)(tids, mreq->tid_req, &resp, tids->cookie))) {
    /* set-up an error response */
    (*mresp)->tid_resp->result = TID_ERROR;
    if (!(*mresp)->tid_resp->err_msg)	/* Use msg set by handler, if any */
      (*mresp)->tid_resp->err_msg = tr_new_name("Internal processing error");
  }
  else {
    /* set-up a success response */
    (*mresp)->tid_resp->result = TID_SUCCESS;
    (*mresp)->tid_resp->err_msg = NULL;	/* No msg on successful return */
  }
    
  return rc;
}

static int tids_send_response (TIDS_INSTANCE *tids, int conn, gss_ctx_id_t *gssctx, TR_MSG *mresp)
{
  int err;
  char *resp_buf;

  if (NULL == (resp_buf = tr_msg_encode(mresp))) {
    fprintf(stderr, "Error decoding json response.\n");
    return -1;
  }

  printf("Encoded response:\n%s\n", resp_buf);
  
  /* Send the response over the connection */
  if (err = gsscon_write_encrypted_token (conn, *gssctx, resp_buf, 
					  strlen(resp_buf) + 1)) {
    fprintf(stderr, "Error sending response over connection.\n");
    return -1;
  }

  free(resp_buf);

  return 0;
}

static void tids_handle_connection (TIDS_INSTANCE *tids, int conn)
{
  TR_MSG *mreq = NULL;
  TR_MSG *mresp = NULL;
  int rc = 0;
  gss_ctx_id_t gssctx = GSS_C_NO_CONTEXT;

  if (!tids_auth_connection(conn, &gssctx)) {
    fprintf(stderr, "Error authorizing TID Server connection.\n");
    close(conn);
    return;
  }

  printf("Connection authorized!\n");

  while (1) {	/* continue until an error breaks us out */

    if (0 > (rc = tids_read_request(tids, conn, &gssctx, &mreq))) {
      fprintf(stderr, "Error from tids_read_request(), rc = %d.\n", rc);
      return;
    } else if (0 == rc) {
      continue;
    }

    /* Allocate a response structure and populate common fields */
    if ((NULL == (mresp = malloc(sizeof(TR_MSG)))) ||
	(NULL == (mresp->tid_resp = malloc(sizeof(TID_RESP))))) {
      fprintf(stderr, "Error allocating response structure.\n");
      return;
    }

    mresp->msg_type = TID_RESPONSE;
    memset(mresp->tid_resp, 0, sizeof(TID_RESP));

    /* TBD -- handle errors */
    mresp->tid_resp->result = TID_SUCCESS; /* presume success */
    mresp->tid_resp->rp_realm = tr_dup_name(mreq->tid_req->rp_realm);
    mresp->tid_resp->realm = tr_dup_name(mreq->tid_req->realm);
    mresp->tid_resp->comm = tr_dup_name(mreq->tid_req->comm);
    if (mreq->tid_req->orig_coi)
      mresp->tid_resp->orig_coi = tr_dup_name(mreq->tid_req->orig_coi);

    if (0 > (rc = tids_handle_request(tids, mreq, &mresp))) {
      fprintf(stderr, "Error from tids_handle_request(), rc = %d.\n", rc);
      return;
    }

    if (0 > (rc = tids_send_response(tids, conn, &gssctx, mresp))) {
      fprintf(stderr, "Error from tids_send_response(), rc = %d.\n", rc);
      return;
    }
  }  

  return;
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
		void *cookie)
{
  int listen = -1;
  int conn = -1;
  pid_t pid;
  int optval = 1;

  if (0 > (listen = tids_listen(tids, TID_PORT)))
    perror ("Error from tids_listen()");

  setsockopt(listen, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  /* store the caller's request handler & cookie */
  tids->req_handler = req_handler;
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
      exit(0);
    } else {
      close(conn);
    }
  }

  return 1;	/* should never get here */
}

void tids_destroy (TIDS_INSTANCE *tids)
{
  free(tids);
}


