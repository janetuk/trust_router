/*
 * Copyright (c) 2017, JANET(UK)
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
#include <assert.h>

#include <tr_name_internal.h>

/* returns 1 on success */
int test_wildcard_prefix_match(const char *s, const char *wcs, int expect);

int test_wildcards(void);

int test_wildcards(void)
{
  /* various non-wildcard matches with mismatch in different places */
  test_wildcard_prefix_match("test", "test", 1);
  test_wildcard_prefix_match("test", "nest", 0);
  test_wildcard_prefix_match("test", "text", 0);
  test_wildcard_prefix_match("test", "tess", 0);
  test_wildcard_prefix_match("test", "tes", 0);
  test_wildcard_prefix_match("tes", "test", 0);
  test_wildcard_prefix_match("test", "tex", 0);
  test_wildcard_prefix_match("tex", "test", 0);

  /* wildcard matches */
  test_wildcard_prefix_match("test", "*test", 1);
  test_wildcard_prefix_match("teSt", "*test", 1);
  test_wildcard_prefix_match("test", "*est", 1);
  test_wildcard_prefix_match("test", "*st", 1);
  test_wildcard_prefix_match("test", "*t", 1);
  test_wildcard_prefix_match("test", "*", 1);
  test_wildcard_prefix_match("test", "*text", 0);
  test_wildcard_prefix_match("test", "*ext", 0);
  test_wildcard_prefix_match("test", "*tests", 0);
  test_wildcard_prefix_match("test", "tes*", 1);
  test_wildcard_prefix_match("test", "te?t", 1);
  test_wildcard_prefix_match("test", "te???", 0);
  test_wildcard_prefix_match("test", "test*", 1);
  test_wildcard_prefix_match("server1", "*ser*", 1);
  test_wildcard_prefix_match("server1", "ser[a-z]er1", 1);
  test_wildcard_prefix_match("server1", "ser[a-m]er1", 0);
  test_wildcard_prefix_match("ser[v]er1", "ser\\[v\\]er1", 1);
  test_wildcard_prefix_match("ser[v-z]er1", "ser\\[v-z\\]er1", 1);
  test_wildcard_prefix_match("server.test", "ser*", 1);
  test_wildcard_prefix_match("*", "*", 1);
  test_wildcard_prefix_match(" *", " *", 1);
  test_wildcard_prefix_match(" x", " *", 1);
  test_wildcard_prefix_match("*", "* ", 0);
  test_wildcard_prefix_match("test*", "*", 1);
  test_wildcard_prefix_match("test*", "**", 1);
  test_wildcard_prefix_match("testx", "**", 1);
  return 1;

}

int test_wildcard_prefix_match(const char *s, const char *wcs, int expect)
{
  TR_NAME *str=tr_new_name(s);
  TR_NAME *wc_str=tr_new_name(wcs);

  assert(str);
  assert(wc_str);
  printf("Testing whether [%s] matches [%s]\n", s, wcs);
  assert(expect==tr_name_prefix_wildcard_match(str, wc_str));

  tr_free_name(str);
  tr_free_name(wc_str);
  return 1;
}

int main(void)
{
  assert(test_wildcards());

  printf("Success.\n");
  return 0;
}
