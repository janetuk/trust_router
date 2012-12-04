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

#include <gsscon.h>
#include <tpq.h>

TPQC_INSTANCE *tpqc_create ()
{
  TPQC_INSTANCE *tpqc = NULL;

  if (tpqc = malloc(sizeof(TPQC_INSTANCE)))
    memset(tpqc, 0, sizeof(TPQC_INSTANCE));

  return tpqc;
}

int tpqc_open_connection (TPQC_INSTANCE *tpqc, 
			  char *server)
{
  int err = 0;
  int conn = -1;
  gss_ctx_id_t gssContext = GSS_C_NO_CONTEXT;


  err = gsscon_connect(server, TPQ_PORT, &conn);
  if (!err)
    err = fsscon_active_authenticate(conn, NULL, "trustquery", &gssContext);

  if (!err)
    return conn;
  else
    return -1;
}

int tpqc_send_request (TPQC_INSTANCE *tpqc, 
		       int conn, 
		       char *realm, 
		       char *coi,
		       TPQC_RESP_FUNC *resp_handler,
		       void *cookie)

{

}

void tpqc_destroy (TPQC_INSTANCE *tpqc)
{
  if (tpqc)
    free(tpqc);
}




