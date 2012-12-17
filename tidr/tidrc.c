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
#include <jansson.h>

#include <gsscon.h>
#include <tidr.h>

TIDRC_INSTANCE *tidrc_create ()
{
  TIDRC_INSTANCE *tidrc = NULL;

  if (tidrc = malloc(sizeof(TIDRC_INSTANCE)))
    memset(tidrc, 0, sizeof(TIDRC_INSTANCE));

  return tidrc;
}

int tidrc_open_connection (TIDRC_INSTANCE *tidrc, 
			  char *server,
			  gss_ctx_id_t *gssctx)
{
  int err = 0;
  int conn = -1;

  err = gsscon_connect(server, TIDR_PORT, &conn);

  if (!err)
    err = gsscon_active_authenticate(conn, NULL, "tempidrequest", gssctx);

  if (!err)
    return conn;
  else
    return -1;
}

int tidrc_send_request (TIDRC_INSTANCE *tidrc, 
		       int conn, 
		       gss_ctx_id_t gssctx,
		       char *realm, 
		       char *coi,
		       TIDRC_RESP_FUNC *resp_handler,
		       void *cookie)

{
  json_t *jreq;
  int err;
  char *req_buf;
  char *resp_buf;
  size_t resp_buflen = 0;

  /* Create a json TIDR request */
  if (NULL == (jreq = json_object())) {
    fprintf(stderr,"Error creating json object.\n");
    return -1;
  }

  if (0 > (err = json_object_set_new(jreq, "type", json_string("tidr_request")))) {
    fprintf(stderr, "Error adding type to request.\n");
    return -1;
  }

  /* Insert realm and coi into the json request */
  if (0 > (err = json_object_set_new(jreq, "realm", json_string(realm)))) {
    fprintf(stderr, "Error adding realm to request.\n");
    return -1;
  }
  if (0 > (err = json_object_set_new(jreq, "coi", json_string(coi)))) {
    fprintf(stderr, "Error adding coi to request.\n");
    return -1;
  }

  /* Generate half of a D-H exchange -- TBD */
  /* Insert D-H information into the request -- TBD */

  /* Encode the json request */
  if (NULL == (req_buf = json_dumps(jreq, 0))) {
    fprintf(stderr, "Error encoding json request.\n");
    return -1;
  }
  
  printf("Encoded request:\n%s\n", req_buf);
  
  /* Send the request over the connection */
  if (err = gsscon_write_encrypted_token (conn, gssctx, req_buf, 
					  strlen(req_buf) + 1)) {
    fprintf(stderr, "Error sending request over connection.\n");
    return -1;
  }

  free(req_buf);

  /* read the response from the connection */

  if (err = gsscon_read_encrypted_token(conn, gssctx, &resp_buf, &resp_buflen)) {
    if (resp_buf)
      free(resp_buf);
    return -1;
  }

  fprintf(stdout, "Response Received, %d bytes.\n", resp_buflen);

  /* Parse response -- TBD */

  /* Call the caller's response function */
  (*resp_handler)(tidrc, NULL, cookie);

  if (resp_buf)
    free(resp_buf);

  return 0;
}

void tidrc_destroy (TIDRC_INSTANCE *tidrc)
{
  if (tidrc)
    free(tidrc);
}




