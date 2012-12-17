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

#include <tidr.h>

int tidrs_req_handler (TIDRS_INSTANCE * tidrs,
		      TIDR_REQ *req, 
		      TIDR_RESP *resp,
		      void *cookie)
{
  printf("Request received! Realm = %s, COI = %s\n", req->realm->buf, req->coi->buf);
  if (tidrs)
    tidrs->req_count++;

  if ((NULL == (resp->realm = tr_dup_name(req->realm))) ||
      (NULL == (resp->coi = tr_dup_name(req->coi)))) {
    printf ("Error in tidr_dup_name, not responding.\n");
    return 1;
  }

  return 0;
}


int main (int argc, 
	  const char *argv[]) 
{
  static TIDRS_INSTANCE *tidrs;
  int rc = 0;

  /* Parse command-line arguments */ 
  if (argc != 1)
    printf("Unexpected arguments, ignored.\n");

  /* Create a TIDR server instance */
  if (NULL == (tidrs = tidrs_create())) {
    printf("Error in tidrs_create().  Exiting.\n");
    return 1;
  }

  /* Start-up the server, won't return unless there is an error. */
  rc = tidrs_start(tidrs, &tidrs_req_handler , NULL);
  
  printf("Error in tidrs_start(), rc = %d. Exiting.\n");

  /* Clean-up the TIDR server instance */
  tidrs_destroy(tidrs);

  return 1;
}

