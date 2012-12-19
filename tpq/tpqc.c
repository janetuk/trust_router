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

#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>

#include <gsscon.h>
#include <tr_dh.h>
#include <tpq.h>

char tmp_key[32] = 
  {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
   0x19, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
int tmp_len = 32;

TPQC_INSTANCE *tpqc_create ()
{
  TPQC_INSTANCE *tpqc = NULL;

  if (tpqc = malloc(sizeof(TPQC_INSTANCE))) 
    memset(tpqc, 0, sizeof(TPQC_INSTANCE));
  else
    return NULL;

  /* TBD -- Generate random private key */
  tpqc->priv_key = tmp_key;
  tpqc->priv_len = tmp_len;

  if (NULL == (tpqc->priv_dh = tr_create_dh_params(tpqc->priv_key, tpqc->priv_len))) {
    free (tpqc);
    return NULL;
  }

  fprintf(stderr, "TPQC DH Parameters:\n");
  DHparams_print_fp(stdout, tpqc->priv_dh);
  fprintf(stderr, "\n");

  return tpqc;
}

void tpqc_destroy (TPQC_INSTANCE *tpqc)
{
  if (tpqc)
    free(tpqc);
}

int tpqc_open_connection (TPQC_INSTANCE *tpqc, 
			  char *server,
			  gss_ctx_id_t *gssctx)
{
  int err = 0;
  int conn = -1;

  err = gsscon_connect(server, TPQ_PORT, &conn);

  if (!err)
    err = gsscon_active_authenticate(conn, NULL, "trustquery", gssctx);

  if (!err)
    return conn;
  else
    return -1;
}

int tpqc_send_request (TPQC_INSTANCE *tpqc, 
		       int conn, 
		       gss_ctx_id_t gssctx,
		       char *realm, 
		       char *coi,
		       TPQC_RESP_FUNC *resp_handler,
		       void *cookie)

{
  json_t *jreq;
  int err;
  char *req_buf;
  char *resp_buf;
  size_t resp_buflen = 0;

  /* Create a json TPQ request */
  if (NULL == (jreq = json_object())) {
    fprintf(stderr,"Error creating json object.\n");
    return -1;
  }

  if (0 > (err = json_object_set_new(jreq, "type", json_string("tpq_request")))) {
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
  (*resp_handler)(tpqc, NULL, cookie);

  if (resp_buf)
    free(resp_buf);

  return 0;
}





