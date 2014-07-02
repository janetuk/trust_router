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
#include <jansson.h>

#include <tr_filter.h>
#include <trust_router/tr_constraint.h>

/* Returns TRUE (1) if the the string (str) matchs the wildcard string (wc_str), FALSE (0) if not.
 */
int tr_prefix_wildcard_match (const char *str, const char *wc_str) {
  const char *wc_post = wc_str;
  size_t len = 0;
  size_t wc_len = 0;

  if ((!str) || (!wc_str))
    return 0;

  len = strlen(str);
  if (0 == (wc_len = strlen(wc_str)))
    return 0;

  /* TBD -- skip leading white space? */
  if ('*' == wc_str[0]) {
    wc_post = &(wc_str[1]);
    wc_len--;
  }else if (len != wc_len)
    return 0;


  if (wc_len > len)
    return 0;
  
  if (0 == strcmp(&(str[len-wc_len]), wc_post)) {
    return 1;
  }
  else
    return 0;
  }

TR_CONSTRAINT_SET *tr_constraint_set_from_fline (TR_FLINE *fline)
{
  json_t *cset = NULL;

  if (!fline)
    return NULL;

  if (fline->realm_cons)
    tr_constraint_add_to_set((TR_CONSTRAINT_SET **)&cset, fline->realm_cons);
  if (fline->domain_cons)
    tr_constraint_add_to_set((TR_CONSTRAINT_SET **)&cset, fline->domain_cons);
  
   return cset;
}

/* A constraint set is represented in json as an array of constraint
 * objects.  So, a constraint set (cset) that consists of one realm
 * constraint and one domain constraint might look like:
 *
 *	{cset: [{domain: [a.com, b.co.uk]},
 *	        {realm: [c.net, d.org]}]}
 */

void tr_constraint_add_to_set (TR_CONSTRAINT_SET **cset, TR_CONSTRAINT *cons)
{
  json_t *jcons = NULL;
  json_t *jmatches = NULL;
  int i = 0;

  if ((!cset) || (!cons))
    return;

  /* If we don't already have a json object, create one */
  if (!(*cset))
    *cset = json_array();

  /* Create a json object representing cons */
  jmatches = json_array();
  jcons = json_object();

  for (i = 0; ((i < TR_MAX_CONST_MATCHES) && (NULL != cons->matches[i])); i++) {
    json_array_append_new(jmatches, json_string(cons->matches[i]->buf));
  }

  json_object_set_new(jcons, cons->type->buf, jmatches);
  
  /* Add the created object to the cset object */
  json_array_append_new(*cset, jcons);
} 

