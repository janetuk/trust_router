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

#include <tr.h>

int static tids_req_handler (TIDS_INSTANCE * tids,
		      TID_REQ *req, 
		      TID_RESP **resp,
		      void *cookie)
{
  printf("Request received! Realm = %s, Comm = %s\n", req->realm->buf, req->comm->buf);
  if (tids)
    tids->req_count++;

  return 0;
}

int main (int argc, const char *argv[])
{
  TIDS_INSTANCE *tids = 0;
  int err;
  FILE *cfg_file = 0;

  /* parse command-line arguments -- TBD */

  /* open the configuration file*/
  cfg_file = fopen ("tr.cfg", "r");

  /* read initial configuration */
  if (0 != (err = tr_read_config (cfg_file))) {
    printf ("Error reading configuration, err = %d.\n", err);
    return 1;
  }

  /* initialize the trust path query server instance */
  if (0 == (tids = tids_create ())) {
    printf ("Error initializing Trust Path Query Server instance.\n");
    return 1;
  }

  /* start the trust path query server, won't return unless there is an error. */
  if (0 != (err = tids_start(tids, &tids_req_handler, NULL))) {
    printf ("Error starting Trust Path Query Server, err = %d.\n", err);
    return err;
  }

  tids_destroy(tids);
  return 0;
}
