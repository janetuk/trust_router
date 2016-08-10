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

#include <trust_router/tr_name.h>

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

  if (new = malloc(sizeof(TR_NAME))) {
    new->len = strlen(name);
    if (new->buf = malloc((new->len)+1)) {
      strcpy(new->buf, name);
    } else {
      free(new);
      new=NULL;
    }
  }
  return new;
}

TR_NAME *tr_dup_name (TR_NAME *from)
{
  TR_NAME *to;

  if (!from) {
    return NULL;
  }

  if (NULL != (to = malloc(sizeof(TR_NAME)))) {
    to->len = from->len;
    if (NULL != (to->buf = malloc(to->len+1))) {
      strncpy(to->buf, from->buf, from->len);
      to->buf[to->len] = 0;	/* NULL terminate for debugging printf()s */
    }
  }
  return to;
}

int tr_name_cmp(TR_NAME *one, TR_NAME *two)
{
  int len=one->len;
  int cmp=0;

  if (two->len<one->len)
    len=two->len; /* len now min(one->len,two->len) */

  cmp=strncmp(one->buf, two->buf, len);
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

void tr_name_strlcat(char *dest, const TR_NAME *src, size_t len)
{
  size_t used_len;
  if (src->len >= len)
    used_len = len-1;
  else used_len = src->len;
  if (used_len > 0)
    strncat(dest, src->buf, used_len);
  else dest[0] = '\0';
}

  
char * tr_name_strdup(TR_NAME *src)
{
  char *s = calloc(src->len+1, 1);
  if (s) {
    memcpy(s, src->buf, src->len);
    s[src->len] = '\0';
  }
  return s;
}
