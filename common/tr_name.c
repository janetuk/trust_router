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
#include <string.h>
#include <jansson.h>

#include <tr_name_internal.h>

void tr_free_name (TR_NAME *name)
{
  if (name->buf) {
    free (name->buf);
    name->buf = NULL;
  }

  free(name);
}

TR_NAME *tr_new_name (const char *name)
{
  TR_NAME *new;

  new = malloc(sizeof(TR_NAME));
  if (new) {
    new->len = (int) strlen(name);
    new->buf = malloc(1 + (size_t) new->len);
    if (new->buf) {
      strcpy(new->buf, name);
    } else {
      free(new);
      new=NULL;
    }
  }
  return new;
}

TR_NAME *tr_dup_name (const TR_NAME *from)
{
  TR_NAME *to;

  if (!from) {
    return NULL;
  }

  if (NULL != (to = malloc(sizeof(TR_NAME)))) {
    to->len = from->len;
    if (NULL != (to->buf = malloc(1 + (size_t) to->len))) {
      strncpy(to->buf, from->buf, (size_t) from->len);
      to->buf[to->len] = 0;	/* NULL terminate for debugging printf()s */
    }
  }
  return to;
}

int tr_name_cmp(const TR_NAME *one, const TR_NAME *two)
{
  int len=one->len;
  int cmp=0;

  if (two->len<one->len)
    len=two->len; /* len now min(one->len,two->len) */

  cmp=strncmp(one->buf, two->buf, (size_t) len);
  if (cmp==0) {
    if (one->len<two->len)
      return -1;
    else if (one->len==two->len)
      return 0;
    else
      return 1;
  }
  return cmp;
}

/**
 * Compare a TR_NAME with a null-terminated string.
 *
 * @param one TR_NAME to compare
 * @param two_str Ordinary C null-terminated string
 * @return 0 on match, <0 if one precedes two, >0 if two precedes one
 */
int tr_name_cmp_str(const TR_NAME *one, const char *two_str)
{
  TR_NAME *two=tr_new_name(two_str);
  int cmp=tr_name_cmp(one, two);
  tr_free_name(two);
  return cmp;
}

/**
 * Compare strings, allowing one to have a single '*' as the wildcard character if it is the first character.
 * Leading whitespace is significant.
 *
 * @param str Fixed string to compare
 * @param wc_str Wildcard string to compare
 * @return 1 if the the string (str) matches the wildcard string (wc_str), 0 if not.
 *
 */
int tr_name_prefix_wildcard_match(const TR_NAME *str, const TR_NAME *wc_str)
{
  const char *wc_post=NULL;
  size_t wc_len = 0;

  if ((!str) || (!wc_str))
    return 0;

  wc_len = (size_t) wc_str->len;
  if (wc_len == 0)
    return 0;

  if ('*' == wc_str->buf[0]) {
    /* Wildcard, so the actual compare will start at the second character of wc_str */
    wc_post = wc_str->buf + 1;
    wc_len--;
  } else if (str->len == wc_len) {
    /* No wildcard, but the strings are the same length so may match.
     * Compare the full strings. */
    wc_post=wc_str->buf;
    wc_len = (size_t) wc_str->len;
  } else {
    /* No wildcard and strings are different length, so no match */
    return 0;
  }

  /* A match is not possible if the fixed part of the wildcard string is longer than
   * the string to match it against. */
  if (wc_len > str->len)
    return 0;

  /* Now we compare the last wc_len characters of str against wc_post */
  return (0 == strncmp(str->buf + str->len - wc_len, wc_post, wc_len));
}

void tr_name_strlcat(char *dest, const TR_NAME *src, size_t len)
{
  size_t used_len;
  if (src->len >= len)
    used_len = len-1;
  else
    used_len = (size_t) src->len;
  if (used_len > 0)
    strncat(dest, src->buf, used_len);
  else dest[0] = '\0';
}


char * tr_name_strdup(const TR_NAME *src)
{
  char *s = calloc(1 + (size_t) src->len, 1);
  if (s) {
    memcpy(s, src->buf, (size_t) src->len);
    s[src->len] = '\0';
  }
  return s;
}

json_t *tr_name_to_json_string(const TR_NAME *src)
{
  char *s=tr_name_strdup(src);
  json_t *js=json_string(s);
  if (s!=NULL)
    free(s);
  return js;
}

TR_NAME *tr_name_cat(const TR_NAME *n1, const TR_NAME *n2)
{
  char *s=malloc((size_t) n1->len + (size_t) n2->len + 1);
  TR_NAME *name=NULL;

  if (s==NULL)
    return NULL;
  *s=0;
  strncat(s, n1->buf, (size_t) n1->len);
  strncat(s, n2->buf, (size_t) n2->len);
  name=tr_new_name(s);
  free(s);
  return name;
}
