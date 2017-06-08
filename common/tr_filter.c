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
#include <strings.h>
#include <talloc.h>
#include <assert.h>

#include <tr_filter.h>
#include <trp_internal.h>
#include <tid_internal.h>

/* Function types for handling filter fields generally. All target values
 * are represented as strings in a TR_NAME.
 */
typedef int (*TR_FILTER_FIELD_CMP)(void *target, TR_NAME *val); /* returns 1 on match, 0 on no match */
typedef TR_NAME *(*TR_FILTER_FIELD_GET)(void *target); /* returns string form of the field value */

/* static handler prototypes */
static int tr_ff_cmp_tid_rp_realm(void *rp_req_arg, TR_NAME *val);
static TR_NAME *tr_ff_get_tid_rp_realm(void *rp_req_arg);
static int tr_ff_cmp_trp_info_type(void *inforec_arg, TR_NAME *val);
static TR_NAME *tr_ff_get_trp_info_type(void *inforec_arg);

/**
 * Filter field handler table
 */
struct tr_filter_field_entry {
    TR_FILTER_TYPE filter_type;
    const char *name;
    TR_FILTER_FIELD_CMP cmp;
    TR_FILTER_FIELD_GET get;
};
static struct tr_filter_field_entry tr_filter_field_table[] = {
    {TR_FILTER_TYPE_TID_INBOUND, "rp_realm", tr_ff_cmp_tid_rp_realm, tr_ff_get_tid_rp_realm},
    {TR_FILTER_TYPE_TRP_INBOUND, "info_type", tr_ff_cmp_trp_info_type, tr_ff_get_trp_info_type},
    {TR_FILTER_TYPE_TRP_OUTBOUND, "info_type", tr_ff_cmp_trp_info_type, tr_ff_get_trp_info_type},
    {TR_FILTER_TYPE_UNKNOWN, NULL } /* This must be the final entry */
};

static struct tr_filter_field_entry *tr_filter_field_entry(TR_FILTER_TYPE filter_type, TR_NAME *field_name)
{
  unsigned int ii;

  for (ii=0; tr_filter_field_table[ii].filter_type!=TR_FILTER_TYPE_UNKNOWN; ii++) {
    if ((tr_filter_field_table[ii].filter_type==filter_type)
        && (tr_name_cmp_str(field_name, tr_filter_field_table[ii].name)==0)) {
      return tr_filter_field_table+ii;
    }
  }
  return NULL;
}

static int tr_ff_cmp_tid_rp_realm(void *rp_req_arg, TR_NAME *val)
{
  TID_REQ *req=talloc_get_type_abort(rp_req_arg, TID_REQ);
  assert(req);
  return 0==tr_name_cmp(val, req->rp_realm);
}

static TR_NAME *tr_ff_get_tid_rp_realm(void *rp_req_arg)
{
  TID_REQ *req=talloc_get_type_abort(rp_req_arg, TID_REQ);
  assert(req);
  return tr_dup_name(req->rp_realm);
}

static int tr_ff_cmp_trp_info_type(void *inforec_arg, TR_NAME *val)
{
  TRP_INFOREC *inforec=talloc_get_type_abort(inforec_arg, TRP_INFOREC);
  char *valstr=NULL;
  int val_type=0;

  assert(val);
  assert(inforec);

  /* nothing matches unknown */
  if (inforec->type==TRP_INFOREC_TYPE_UNKNOWN)
    return 0;

  valstr = tr_name_strdup(val); /* get this as an official null-terminated string */
  val_type = trp_inforec_type_from_string(valstr);
  free(valstr);

  return (val_type==inforec->type);
}

static TR_NAME *tr_ff_get_trp_info_type(void *inforec_arg)
{
  TRP_INFOREC *inforec=talloc_get_type_abort(inforec_arg, TRP_INFOREC);
  return tr_new_name(trp_inforec_type_to_string(inforec->type));
}

/**
 * Apply a filter to a target record or TID request.
 *
 * If one of the filter lines matches, out_action is set to the applicable action. If constraints
 * is not NULL, the constraints from the matching filter line will be added to the constraint set
 * *constraints, or to a new one if *constraints is NULL. In this case, TR_FILTER_MATCH will be
 * returned.
 *
 * If there is no match, returns TR_FILTER_NO_MATCH, out_action is undefined, and constraints
 * will not be changed.
 *
 * @param target Record or request to which the filter is applied
 * @param filt Filter to apply
 * @param constraints Pointer to existing set of constraints (NULL if not tracking constraints)
 * @param out_action Action to be carried out (output)
 * @return TR_FILTER_MATCH or TR_FILTER_NO_MATCH
 */
int tr_filter_apply(void *target,
                    TR_FILTER *filt,
                    TR_CONSTRAINT_SET **constraints,
                    TR_FILTER_ACTION *out_action)
{
  unsigned int ii=0, jj=0;
  int retval=TR_FILTER_NO_MATCH;

  /* Default action is reject */
  *out_action = TR_FILTER_ACTION_REJECT;

  /* Validate filter */
  if ((filt==NULL) || (filt->type==TR_FILTER_TYPE_UNKNOWN))
    return TR_FILTER_NO_MATCH;

  /* Step through filter lines looking for a match. If a line matches, retval
   * will be set to TR_FILTER_MATCH, so stop then. */
  for (ii=0, retval=TR_FILTER_NO_MATCH;
       (ii<TR_MAX_FILTER_LINES) && (retval==TR_FILTER_NO_MATCH);
       ii++) {
    /* skip empty lines (these shouldn't really happen) */
    if (filt->lines[ii]==NULL)
      continue;

    /* Assume we are going to succeed. If any specs fail to match, we'll set
     * this to TR_FILTER_NO_MATCH. */
    retval=TR_FILTER_MATCH;
    for (jj=0; jj<TR_MAX_FILTER_SPECS; jj++) {
      /* skip empty specs (these shouldn't really happen either) */
      if (filt->lines[ii]->specs[jj]==NULL)
        continue;

      if (!tr_fspec_matches(filt->lines[ii]->specs[jj], filt->type, target)) {
        retval=TR_FILTER_NO_MATCH; /* set this in case this is the last filter line */
        break; /* give up on this filter line */
      }
    }
  }

  if (retval==TR_FILTER_MATCH) {
    /* Matched line ii. Grab its action and constraints. */
    *out_action = filt->lines[ii]->action;
    if (constraints!=NULL) {
      /* if either constraint is missing, these are no-ops */
      tr_constraint_add_to_set(constraints, filt->lines[ii]->realm_cons);
      tr_constraint_add_to_set(constraints, filt->lines[ii]->domain_cons);
    }
  }

  return retval;
}

int tr_filter_process_rp_permitted(TR_NAME *rp_realm,
                                   TR_FILTER *rpp_filter,
                                   TR_CONSTRAINT_SET *in_constraints,
                                   TR_CONSTRAINT_SET **out_constraints,
                                   TR_FILTER_ACTION *out_action)
{
  int i = 0, j = 0;

  *out_action = TR_FILTER_ACTION_REJECT;
  *out_constraints = NULL;

  /* If this isn't a valid rp_permitted filter, return no match. */
  if ((!rpp_filter) ||
      (TR_FILTER_TYPE_TID_INBOUND != rpp_filter->type)) {
    return TR_FILTER_NO_MATCH;
  }

  /* Check if there is a match for this filter. */
  for (i = 0; i < TR_MAX_FILTER_LINES; i++) {
    for (j = 0; j < TR_MAX_FILTER_SPECS; j++) {

      if ((rpp_filter->lines[i]) &&
          (rpp_filter->lines[i]->specs[j]) &&
          (tr_fspec_matches(rpp_filter->lines[i]->specs[j], 0, rp_realm))) { /* todo: fix or remove */
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

static int tr_fspec_destructor(void *obj)
{
  TR_FSPEC *fspec = talloc_get_type_abort(obj, TR_FSPEC);
  size_t ii;

  if (fspec->field != NULL)
    tr_free_name(fspec->field);
  for (ii=0; ii<TR_MAX_FILTER_SPEC_MATCHES; ii++) {
    if (fspec->match[ii] != NULL)
      tr_free_name(fspec->match[ii]);
  }
  return 0;
}

TR_FSPEC *tr_fspec_new(TALLOC_CTX *mem_ctx)
{
  TR_FSPEC *fspec = talloc(mem_ctx, TR_FSPEC);
  size_t ii=0;

  if (fspec != NULL) {
    fspec->field = NULL;
    for (ii=0; ii<TR_MAX_FILTER_SPEC_MATCHES; ii++)
      fspec->match[ii] = NULL;

    talloc_set_destructor((void *)fspec, tr_fspec_destructor);
  }
  return fspec;
}

void tr_fspec_add_match(TR_FSPEC *fspec, TR_NAME *match)
{
  size_t ii;
  for (ii=0; ii<TR_MAX_FILTER_SPEC_MATCHES; ii++) {
    if (fspec->match[ii]==NULL) {
      fspec->match[ii]=match;
      break;
    }
  }
  /* TODO: handle case that adding the match failed */
}

/* returns 1 if the spec matches */
int tr_fspec_matches(TR_FSPEC *fspec, TR_FILTER_TYPE ftype, void *target)
{
  struct tr_filter_field_entry *field=NULL;
  TR_NAME *name=NULL;
  size_t ii=0;

  if (fspec==NULL)
    return 0;

  /* Look up how to handle the requested field */
  field = tr_filter_field_entry(ftype, fspec->field);
  if (field==NULL)
    return 0;

  name=field->get(target);
  for (ii=0; ii<TR_MAX_FILTER_SPEC_MATCHES; ii++) {
    if (fspec->match[ii]!=NULL) {
      if (tr_name_prefix_wildcard_match(name, fspec->match[ii]))
        return 1;
    }
  }
  return 0;
}

void tr_fline_free(TR_FLINE *fline)
{
  talloc_free(fline);
}

TR_FLINE *tr_fline_new(TALLOC_CTX *mem_ctx)
{
  TR_FLINE *fl = talloc(mem_ctx, TR_FLINE);
  int ii = 0;

  if (fl != NULL) {
    fl->action = TR_FILTER_ACTION_UNKNOWN;
    fl->realm_cons = NULL;
    fl->domain_cons = NULL;
    for (ii = 0; ii < TR_MAX_FILTER_SPECS; ii++)
      fl->specs[ii] = NULL;
  }
  return fl;
}

TR_FILTER *tr_filter_new(TALLOC_CTX *mem_ctx)
{
  TR_FILTER *f = talloc(mem_ctx, TR_FILTER);
  int ii = 0;

  if (f != NULL) {
    f->type = TR_FILTER_TYPE_UNKNOWN;
    for (ii = 0; ii < TR_MAX_FILTER_LINES; ii++)
      f->lines[ii] = NULL;
  }
  return f;
}

void tr_filter_free(TR_FILTER *filt)
{
  talloc_free(filt);
}

void tr_filter_set_type(TR_FILTER *filt, TR_FILTER_TYPE type)
{
  filt->type = type;
}

TR_FILTER_TYPE tr_filter_get_type(TR_FILTER *filt)
{
  return filt->type;
}

/**
 * Check that a filter is valid, i.e., can be processed.
 *
 * @param filt Filter to verify
 * @return 1 if the filter is valid, 0 otherwise
 */
int tr_filter_validate(TR_FILTER *filt)
{
  size_t ii=0, jj=0, kk=0;

  if (!filt)
    return 0;

  /* check that we recognize the type */
  switch(filt->type) {
    case TR_FILTER_TYPE_TID_INBOUND:
    case TR_FILTER_TYPE_TRP_INBOUND:
    case TR_FILTER_TYPE_TRP_OUTBOUND:
      break;

    default:
      return 0; /* if we get here, either TR_FILTER_TYPE_UNKNOWN or an invalid value was found */
  }
  for (ii=0; ii<TR_MAX_FILTER_LINES; ii++) {
    if (filt->lines[ii]==NULL)
      continue; /* an empty filter line is valid */

    /* check that we recognize the action */
    switch(filt->lines[ii]->action) {
      case TR_FILTER_ACTION_ACCEPT:
      case TR_FILTER_ACTION_REJECT:
        break;

      default:
        /* if we get here, either TR_FILTER_ACTION_UNKNOWN or an invalid value was found */
        return 0;
    }

    for (jj=0; jj<TR_MAX_FILTER_SPECS; jj++) {
      if (filt->lines[ii]->specs[jj]==NULL)
        continue; /* an empty filter spec is valid */

      if (!tr_filter_validate_spec_field(filt->type, filt->lines[ii]->specs[jj]))
        return 0;

      /* check that at least one match is non-null */
      for (kk=0; kk<TR_MAX_FILTER_SPEC_MATCHES; kk++) {
        if (filt->lines[ii]->specs[jj]->match[kk]!=NULL)
          break;
      }
      if (kk==TR_MAX_FILTER_SPEC_MATCHES)
        return 0;
    }
  }

  /* We ran the gauntlet. Success! */
  return 1;
}

int tr_filter_validate_spec_field(TR_FILTER_TYPE ftype, TR_FSPEC *fspec)
{
  if ((fspec==NULL) || (tr_filter_field_entry(ftype, fspec->field)==NULL))
    return 0; /* unknown field */

  return 1;
}