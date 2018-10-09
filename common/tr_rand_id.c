/*
 * Copyright (c) 2018, JANET(UK)
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
#include <string.h>
#include <openssl/rand.h>
#include <talloc.h>

#include <tr_rand_id.h>

static char *bytes_to_hex(TALLOC_CTX *mem_ctx, const unsigned char *bytes, size_t len)
{
  char *hex = talloc_size(mem_ctx, 1 + len * 2 * sizeof(char));
  char *p = NULL;

  if (hex) {
    p = hex;
    while(len--) {
      p += sprintf(p, "%02x", *(bytes++));
    }
  }

  return hex;
}

/**
 * Generate n random bytes of data
 *
 * @param dst destination buffer, at least n bytes long
 * @param n number of bytes to generate
 * @return -1 on error
 */
static int random_bytes(unsigned char *dst, size_t n)
{
  return RAND_bytes(dst, n);
}

#define ID_LENGTH 15
/**
 * Generate a random ID
 *
 * @param mem_ctx talloc context for the result
 * @return random string of hex characters or null if it is unable to generate them
 */
char *tr_random_id(TALLOC_CTX *mem_ctx)
{
  unsigned char bytes[ID_LENGTH];
  char *hex = NULL;

  if (random_bytes(bytes, ID_LENGTH) >= 0)
    hex = bytes_to_hex(mem_ctx, bytes, ID_LENGTH);

  return hex;
}
