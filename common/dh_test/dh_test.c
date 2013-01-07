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
#include <stdio.h>

#include <tr_dh.h>

char tmp_key1[32] = 
  {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
   0x19, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

char tmp_key2[32] = 
  {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
   0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
   0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
   0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};

int tmp_len = 32;

int main (int argc, 
	  const char *argv[]) 
{
  DH *c_dh = NULL;
  DH *s_dh = NULL;
  char *c_keybuf = NULL;
  char *s_keybuf = NULL;
  int dh_err = 0, c_keylen = 0, s_keylen = 0;

  /* TBD -- Generate random private keys */

  /* Generate initial DH params on the client side */
  if (NULL == (c_dh = tr_create_dh_params(tmp_key1, tmp_len))) {
    printf("Error: Can't create client DH params, exiting.\n");
    exit(1);
  }

  fprintf(stderr, "Client DH Parameters:\n");
  DHparams_print_fp(stdout, c_dh);
  fprintf(stderr, "\n");

  /*** Would now send DH params and client's public key to the server ***/

  /* Generate DH params on the server side */
  if (NULL == (s_dh = tr_create_matching_dh(tmp_key2, tmp_len, c_dh))) {
    printf("Error: Can't create server server DH params, exiting.\n");
    exit(1);
  }

  fprintf(stderr, "Server DH Parameters:\n");
  DHparams_print_fp(stdout, s_dh);
  fprintf(stderr, "\n");

  /*** Would now send server's pub key to client ***/

  /* Compute key on client */
  if (NULL == (c_keybuf = malloc(DH_size(c_dh)))) {
    printf ("Error: Can't allocate client keybuf, exiting.\n");
    exit(1);
  }
  if (0 > (c_keylen = tr_compute_dh_key(c_keybuf, 
				      DH_size(c_dh), 
				      s_dh->pub_key, 
				      c_dh))) {
    
  }
  
  /* Compute key on server */
  if (NULL == (s_keybuf = malloc(DH_size(c_dh)))) {
    printf ("Error: Can't allocate server keybuf, exiting.\n");
    exit(1);
  }
  if (0 > (s_keylen = tr_compute_dh_key(s_keybuf, 
				      DH_size(s_dh), 
				      c_dh->pub_key, 
				      s_dh))) {
    
  }
  
  /* Compare the two keys to see if they match */
  if ((c_keylen != s_keylen) &&
      (0 != memcmp(c_keybuf, s_keybuf, c_keylen))) {
    printf("Error: Different keys generated!\n");
    exit(1);
  }

  printf("Success: Identical keys generated, key length = %d!\n", c_keylen);
  exit(0);
}
    


