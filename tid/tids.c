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
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <jansson.h>

#include <gsscon.h>
#include <tid.h>

static int tids_listen (int port) 
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

static int tids_read_request (int conn, gss_ctx_id_t *gssctx, TID_REQ *req)
{
  int err;
  char *buf;
  size_t buflen = 0;

  if (err = gsscon_read_encrypted_token(conn, *gssctx, &buf, &buflen)) {
    if (buf)
      free(buf);
    return -1;
  }

  fprintf(stdout, "Request Received, %d bytes.\n", buflen);

  /* Parse request -- TBD */

  if (buf)
    free(buf);

  return buflen;
}

static int tids_handle_request (TID_REQ *req, TID_RESP *resp) 
{
  return 0;
}

static int tids_send_response (int conn, gss_ctx_id_t *gssctx, TID_RESP *resp)
{
  json_t *jreq;
  int err;
  char *resp_buf;

  /* Create a json TID response */
  if (NULL == (jreq = json_object())) {
    fprintf(stderr,"Error creating json object.\n");
    return -1;
  }

  if (0 > (err = json_object_set_new(jreq, "type", json_string("tid_response")))) {
    fprintf(stderr, "Error adding type to response.\n");
    return -1;
  }
  if (0 > (err = json_object_set_new(jreq, "result", json_string("error")))) {
    fprintf(stderr, "Error adding result to response.\n");
    return -1;
  }
  if (0 > (err = json_object_set_new(jreq, "msg", json_string("No path to realm")))) {
    fprintf(stderr, "Error adding msg to response.\n");
    return -1;
  }

  /* Encode the json response */
  if (NULL == (resp_buf = json_dumps(jreq, 0))) {
    fprintf(stderr, "Error encoding json response.\n");
    return -1;
  }
  
  printf("Encoded response:\n%s\n", resp_buf);
  
  /* Send the request over the connection */
  if (err = gsscon_write_encrypted_token (conn, *gssctx, resp_buf, 
					  strlen(resp_buf) + 1)) {
    fprintf(stderr, "Error sending request over connection.\n");
    return -1;
  }

  free(resp_buf);

  return 0;

}

static void tids_handle_connection (int conn)
{
  TID_REQ req;
  TID_RESP resp;
  int rc;
  gss_ctx_id_t gssctx = GSS_C_NO_CONTEXT;

  if (!tids_auth_connection(conn, &gssctx)) {
    fprintf(stderr, "Error authorizing TID Server connection, rc = %d.\n", rc);
    close(conn);
    return;
  }

  printf("Connection authorized!\n");

  while (1) {	/* continue until an error breaks us out */

    if (0 > (rc = tids_read_request(conn, &gssctx, &req))) {
      fprintf(stderr, "Error from tids_read_request(), rc = %d.\n", rc);
      return;
    } else if (0 == rc) {
      continue;
    }

    if (0 > (rc = tids_handle_request(&req, &resp))) {
      fprintf(stderr, "Error from tids_handle_request(), rc = %d.\n", rc);
      return;
    }

    if (0 > (rc = tids_send_response(conn, &gssctx, &resp))) {
      fprintf(stderr, "Error from tids_send_response(), rc = %d.\n", rc);
      return;
    }
  }  

  return;
}

TIDS_INSTANCE *tids_create ()
{
  TIDS_INSTANCE *tids = 0;
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

  if (0 > (listen = tids_listen(TID_PORT)))
    perror ("Error from tids_listen()");

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
      tids_handle_connection(conn);
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


