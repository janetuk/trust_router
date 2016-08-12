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
#include <talloc.h>

#include <tr_filter.h>


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

      if ((rpp_filter->lines[i]) && 
	  (rpp_filter->lines[i]->specs[j]) && 
	  (tr_prefix_wildcard_match(rp_realm->buf, rpp_filter->lines[i]->specs[j]->match->buf))) {
	*out_action = rpp_filter->lines[i]->action;
	*out_constraints = in_constraints;
	if (rpp_filter->lines[i]->realm_cons)
	  tr_constraint_add_to_set(out_constraints, 
				   rpp_filter->lines[i]->realm_cons);
	if (rpp_filter->lines[i]->domain_cons)
	  tr_constraint_add_to_set(out_constraints, 
				   rpp_filter->lines[i]->domain_cons);

	return TR_FILTER_MATCH;
      }
    }
  }
  /* If there is no match, indicate that. */
  return TR_FILTER_NO_MATCH;
}

void tr_fspec_free(TR_FSPEC *fspec)
{
  talloc_free(fspec);
}

int tr_fspec_destructor(void *obj)
{
  TR_FSPEC *fspec=talloc_get_type_abort(obj, TR_FSPEC);
  if (fspec->field!=NULL)
    tr_free_name(fspec->field);
  if (fspec->match!=NULL)
    tr_free_name(fspec->match);
  return 0;
}

TR_FSPEC *tr_fspec_new(TALLOC_CTX *mem_ctx)
{
  TR_FSPEC *fspec=talloc(mem_ctx, TR_FSPEC);

  if (fspec!=NULL) {
    fspec->field=NULL;
    fspec->match=NULL;
    talloc_set_destructor((void *)fspec, tr_fspec_destructor);
  }
  return fspec;
}

void tr_fline_free(TR_FLINE *fline)
{
  talloc_free(fline);
}

TR_FLINE *tr_fline_new(TALLOC_CTX *mem_ctx)
{
  TR_FLINE *fl=talloc(mem_ctx, TR_FLINE);
  int ii=0;

  if (fl!=NULL) {
    fl->action=TR_FILTER_ACTION_UNKNOWN;
    fl->realm_cons=NULL;
    fl->domain_cons=NULL;
    for (ii=0; ii<TR_MAX_FILTER_SPECS; ii++)
      fl->specs[ii]=NULL;
  }
  return fl;
}

TR_FILTER *tr_filter_new(TALLOC_CTX *mem_ctx)
{
  TR_FILTER *f=talloc(mem_ctx, TR_FILTER);
  int ii=0;

  if (f!=NULL) {
    f->type=TR_FILTER_TYPE_UNKNOWN;
    for (ii=0; ii<TR_MAX_FILTER_LINES; ii++)
      f->lines[ii]=NULL;
  }
  return f;
}

void tr_filter_free(TR_FILTER *filt)
{
  talloc_free(filt);
}

void tr_filter_set_type(TR_FILTER *filt, TR_FILTER_TYPE type)
{
  filt->type=type;
}

TR_FILTER_TYPE tr_filter_get_type(TR_FILTER *filt)
{
  return filt->type;
}
