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
#include <string.h>

#include <trust_router/tr_dh.h>

// char tmp_key1[32] = 
//  {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
//   0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
//   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
//   0x19, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
//
// char tmp_key2[32] = 
//  {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
//   0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
//   0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
//   0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
//
// int tmp_len = 32;

int main (int argc, 
	  const char *argv[]) 
{
  DH *c_dh = NULL;
  DH *s_dh = NULL;
  unsigned char *c_keybuf = NULL;
  unsigned char *s_keybuf = NULL;
  int c_keylen = 0, s_keylen = 0, i = 0;

  /* TBD -- Generate random private keys */

  /* Generate initial DH params on the client side */
  if (NULL == (c_dh = tr_create_dh_params(NULL, 0))) {
    printf("Error: Can't create client DH params, exiting.\n");
    exit(1);
  }

  fprintf(stderr, "Client DH Parameters:\n");
  DHparams_print_fp(stdout, c_dh);
  fprintf(stderr, "\n");

  /*** Would now send DH params and client's public key to the server ***/

  /* Generate DH params on the server side */
  if (NULL == (s_dh = tr_create_matching_dh(NULL, 0, c_dh))) {
    printf("Error: Can't create server server DH params, exiting.\n");
    exit(1);
  }

  fprintf(stdout, "Server DH Parameters:\n");
  DHparams_print_fp(stdout, s_dh);
  fprintf(stdout, "\n");

  /*** Would now send server's pub key to client ***/

  /* Compute key on client */
  if (0 > (c_keylen = tr_compute_dh_key(&c_keybuf, 
				      s_dh->pub_key, 
				      c_dh))) {
    
  }
  
  /* Compute key on server */
  if (0 > (s_keylen = tr_compute_dh_key(&s_keybuf, 
				      c_dh->pub_key, 
				      s_dh))) {
    printf("Error: Can't compute server key.\n");
    exit(1);
  }
  
  /* Print out the client key. */
  printf("Client Key Generated (len = %d):\n", c_keylen);
  for (i = 0; i < c_keylen; i++) {
    printf("%2x", c_keybuf[i]);
  }
  printf("\n");

  /* Print out the server key. */
  printf("Server Key Generated (len = %d):\n", s_keylen);
  for (i = 0; i < s_keylen; i++) {
    printf("%2x", s_keybuf[i]);
  }
  printf("\n");

  /* Compare the two keys to see if they match */
  if ((c_keylen != s_keylen) ||
      (0 != memcmp(c_keybuf, s_keybuf, c_keylen))) {
    printf("Error: Different keys generated!\n");
    exit(1);
  }

  printf("Success: Identical keys generated, key length = %d!\n", c_keylen);
  exit(0);
}
    


