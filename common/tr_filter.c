/*
 * Copyright (c) 2012, 2013, JANET(UK)
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
#include <string.h>
#include <tr_filter.h>

/* Returns TRUE (1) if the the string (str) matchs the wildcard string (wc_str), FALSE (0) if not.
 */
int tr_prefix_wildcard_match (char *str, char *wc_str) {
  char *wc_post = wc_str;
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
  }

  if (wc_len > len)
    return 0;
  
  if (0 == strcmp(&(str[len-wc_len]), wc_post)) {
    return 1;
  }
  else
    return 0;
  }

int tr_filter_process_rp_permitted (TR_NAME *rp_realm, TR_FILTER *rpp_filter, TR_CONSTRAINT_SET *in_constraints, TR_CONSTRAINT_SET **out_constraints, int *out_action) 
{
  int i = 0, j = 0;

  *out_action = TR_FILTER_ACTION_REJECT;
  *out_constraints = NULL;

  /* If this isn't a valid rp_permitted filter, return no match. */
  if ((!rpp_filter) ||
      (TR_FILTER_TYPE_RP_PERMITTED != rpp_filter->type)) {
    return TR_FILTER_NO_MATCH;
  }
  
  /* Check if there is a match for this filter. */
  for (i = 0; i < TR_MAX_FILTER_LINES; i++) {
    for (j = 0; j < TR_MAX_FILTER_SPECS; j++) {
      if (tr_prefix_wildcard_match(rp_realm->buf, rpp_filter->lines[i]->specs[j]->match->buf)) {
	*out_action = rpp_filter->lines[i]->action;
	*out_constraints = rpp_filter->lines[i]->constraints;
	return TR_FILTER_MATCH;
      }
    }
  }
  /* If there is no match, indicate that. */
  return TR_FILTER_NO_MATCH;
}

void tr_filter_free (TR_FILTER *filt) {
  int i = 0, j = 0;

  if (!filt)
    return;

  for (i = 0; i < TR_MAX_FILTER_LINES; i++) {
    if (filt->lines[i]) {
      for (j = 0; j < TR_MAX_FILTER_SPECS; j++) {
	if (filt->lines[i]->specs[j])
	  free(filt->lines[i]->specs[j]);
      }
      free(filt->lines[i]);
    }
  }

  free (filt);
}

