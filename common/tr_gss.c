/*
 * Copyright (c) 2016, JANET(UK)
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

#include <talloc.h>

#include <tr_gss.h>

static int tr_gss_names_destructor(void *obj)
{
  TR_GSS_NAMES *gss_names=talloc_get_type_abort(obj, TR_GSS_NAMES);
  int ii=0;

  for (ii=0; ii<TR_MAX_GSS_NAMES; ii++) {
    if (gss_names->names[ii]!=NULL)
      tr_free_name(gss_names->names[ii]);
  }
  return 0;
}
TR_GSS_NAMES *tr_gss_names_new(TALLOC_CTX *mem_ctx)
{
  TR_GSS_NAMES *gn=talloc(mem_ctx, TR_GSS_NAMES);
  int ii=0;

  if (gn!=NULL) {
    for (ii=0; ii<TR_MAX_GSS_NAMES; ii++)
      gn->names[ii]=NULL;
    talloc_set_destructor((void *)gn, tr_gss_names_destructor);
  }
  return gn;
}

void tr_gss_names_free(TR_GSS_NAMES *gn)
{
  talloc_free(gn);
}

/* returns 0 on success */
int tr_gss_names_add(TR_GSS_NAMES *gn, TR_NAME *new)
{
  int ii=0;

  for (ii=0; ii<TR_MAX_GSS_NAMES; ii++) {
    if (gn->names[ii]==NULL)
      break;
  }
  if (ii!=TR_MAX_GSS_NAMES) {
    gn->names[ii]=new;
    return 0;
  } else
    return -1;
}

int tr_gss_names_matches(TR_GSS_NAMES *gn, TR_NAME *name)
{
  int ii=0;

  if (!gn)
    return 0;

  for (ii=0; ii<TR_MAX_GSS_NAMES; ii++) {
    if ((gn->names[ii]!=NULL) &&
        (0==tr_name_cmp(gn->names[ii], name)))
      return 1;
  }
  return 0;
}

/* iterators */
TR_GSS_NAMES_ITER *tr_gss_names_iter_new(TALLOC_CTX *mem_ctx)
{
  TR_GSS_NAMES_ITER *iter=talloc(mem_ctx, TR_GSS_NAMES_ITER);
  if (iter!=NULL) {
    iter->gn=NULL;
    iter->ii=0;
  }
  return iter;
}

TR_NAME *tr_gss_names_iter_first(TR_GSS_NAMES_ITER *iter, TR_GSS_NAMES *gn)
{
  iter->gn=gn;
  iter->ii=-1;
  return tr_gss_names_iter_next(iter);
}

TR_NAME *tr_gss_names_iter_next(TR_GSS_NAMES_ITER *iter)
{
  for (iter->ii++;
       (iter->ii < TR_MAX_GSS_NAMES) && (iter->gn->names[iter->ii]==NULL);
       iter->ii++) { }

  if (iter->ii<TR_MAX_GSS_NAMES)
    return iter->gn->names[iter->ii];
  
  return NULL;
}

void tr_gss_names_iter_free(TR_GSS_NAMES_ITER *iter)
{
  talloc_free(iter);
}
