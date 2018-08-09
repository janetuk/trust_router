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

#include <stdlib.h>
#include <string.h>
#include <talloc.h>

#include <tr_filter.h>
#include <tid_internal.h>
#include <tr_debug.h>

/**
 * Notes on filter field handlers
 *
 * A dynamic table of fields is maintained. A protocol should register
 * a compare function with signature TR_FILTER_FIELD_CMP and a getter
 * function with signature TR_FILTER_FIELD_GET. These handlers are
 * registered with tr_filter_add_field_handler().
 *
 * Field handlers for the TID protocol are initialized automatically.
 * This could be broken out, but it is unclear that this module will
 * ever be used in programs that do not need to handle TID messages.
 *
 * The filter types must be defined in the TR_FILTER_TYPE enum. This
 * could be done dynamically (like in tr_msg.c), but it's unclear that
 * this would be practically useful.
 */
TR_FILTER_TARGET *tr_filter_target_new(TALLOC_CTX *mem_ctx)
{
  TR_FILTER_TARGET *target=talloc(mem_ctx, TR_FILTER_TARGET);
  if (target) {
    target->trp_inforec=NULL;
    target->trp_upd=NULL;
    target->tid_req=NULL;
  }
  return target;
}
void tr_filter_target_free(TR_FILTER_TARGET *target)
{
  talloc_free(target);
}

/**
 * Create a filter target for a TID request. Does not change the context of the request,
 * so this is only valid until that is freed.
 *
 * @param mem_ctx talloc context for the object
 * @param req TID request object
 * @return pointer to a TR_FILTER_TARGET structure, or null on allocation failure
 */
TR_FILTER_TARGET *tr_filter_target_tid_req(TALLOC_CTX *mem_ctx, TID_REQ *req)
{
  TR_FILTER_TARGET *target=tr_filter_target_new(mem_ctx);
  if (target)
    target->tid_req=req; /* borrowed, not adding to our context */
  return target;
}

/** Handler functions for TID RP_REALM field */
static int tr_ff_cmp_tid_rp_realm(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_name_cmp(tid_req_get_rp_realm(target->tid_req), val);
}

static TR_NAME *tr_ff_get_tid_rp_realm(TR_FILTER_TARGET *target)
{
  return tr_dup_name(tid_req_get_rp_realm(target->tid_req));
}

/** Handlers for TID realm field */
static int tr_ff_cmp_tid_realm(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_name_cmp(tid_req_get_realm(target->tid_req), val);
}

static TR_NAME *tr_ff_get_tid_realm(TR_FILTER_TARGET *target)
{
  return tr_dup_name(tid_req_get_realm(target->tid_req));
}

/** Handlers for TID community field */
static int tr_ff_cmp_tid_comm(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_name_cmp(tid_req_get_comm(target->tid_req), val);
}

static TR_NAME *tr_ff_get_tid_comm(TR_FILTER_TARGET *target)
{
  return tr_dup_name(tid_req_get_comm(target->tid_req));
}

/** Handlers for TID req original_coi field */
static int tr_ff_cmp_tid_orig_coi(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_name_cmp(tid_req_get_orig_coi(target->tid_req), val);
}

static TR_NAME *tr_ff_get_tid_orig_coi(TR_FILTER_TARGET *target)
{
  return tr_dup_name(tid_req_get_orig_coi(target->tid_req));
}

/**
 * Filter field handler table
 */
#define FILTER_FIELD_NAME_LEN 50
struct tr_filter_field_entry {
  TR_FILTER_TYPE filter_type;
  char name[FILTER_FIELD_NAME_LEN+1];
  TR_FILTER_FIELD_CMP *cmp;
  TR_FILTER_FIELD_GET *get;
};
/* As of now, we use 24 of these when the TRP module is present */
#define FILTER_FIELD_TABLE_LEN 30
static struct tr_filter_field_entry tr_filter_field_table[FILTER_FIELD_TABLE_LEN] = {
  /* realm */
  {TR_FILTER_TYPE_TID_INBOUND, "realm", tr_ff_cmp_tid_realm, tr_ff_get_tid_realm},

  /* community */
  {TR_FILTER_TYPE_TID_INBOUND, "comm", tr_ff_cmp_tid_comm, tr_ff_get_tid_comm},

  /* rp_realm */
  {TR_FILTER_TYPE_TID_INBOUND, "rp_realm", tr_ff_cmp_tid_rp_realm, tr_ff_get_tid_rp_realm},

  /* original coi */
  {TR_FILTER_TYPE_TID_INBOUND, "original_coi", tr_ff_cmp_tid_orig_coi, tr_ff_get_tid_orig_coi},

  /* The rest start off as 0 (TYPE_UNKNOWN) */
  {0}
};

int tr_filter_add_field_handler(TR_FILTER_TYPE ftype,
                                const char *name,
                                TR_FILTER_FIELD_CMP *cmp,
                                TR_FILTER_FIELD_GET *get)
{
  size_t ii;
  struct tr_filter_field_entry *handler;

  for (ii=0; ii < FILTER_FIELD_TABLE_LEN; ii++) {
    handler = &(tr_filter_field_table[ii]);
    if ((handler->filter_type == TR_FILTER_TYPE_UNKNOWN)
       || ((handler->filter_type == ftype)
          && (0 == strcmp(name, handler->name)))) {
      /* Entry already exists */
      break;
    }
  }

  if (ii >= FILTER_FIELD_TABLE_LEN) {
    tr_debug("tr_filter_add_field_handler: table full adding filter_type=%d, name=%s",
             ftype,
             name);
    return 0;
  }

  /* Now fill in the table, replacing one if it already existed.
   * If we're here, handler points at the correct entry in the table. */
  handler->filter_type = ftype;
  strncpy(handler->name, name, FILTER_FIELD_NAME_LEN);
  handler->name[FILTER_FIELD_NAME_LEN] = '\0'; /* just to be sure */
  handler->cmp = cmp;
  handler->get = get;

  return 1;
}

/* TODO: support TRP metric field (requires > < comparison instead of wildcard match) */

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
int tr_filter_apply(TR_FILTER_TARGET *target,
                    TR_FILTER *filt,
                    TR_CONSTRAINT_SET **constraints,
                    TR_FILTER_ACTION *out_action)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  TR_FILTER_ITER *filt_iter = tr_filter_iter_new(tmp_ctx);
  TR_FLINE *this_fline = NULL;
  TR_FLINE_ITER *fline_iter = tr_fline_iter_new(tmp_ctx);
  TR_FSPEC *this_fspec = NULL;
  int retval=TR_FILTER_NO_MATCH;

  /* Default action is reject */
  *out_action = TR_FILTER_ACTION_REJECT;

  /* Validate filter */
  if ((filt_iter == NULL) || (fline_iter == NULL) || (filt==NULL) || (filt->type==TR_FILTER_TYPE_UNKNOWN)) {
    talloc_free(tmp_ctx);
    return TR_FILTER_NO_MATCH;
  }

  /* Step through filter lines looking for a match. If a line matches, retval
   * will be set to TR_FILTER_MATCH, so stop then. */
  for (this_fline = tr_filter_iter_first(filt_iter, filt);
       this_fline != NULL;
       this_fline = tr_filter_iter_next(filt_iter)) {
    /* Assume we are going to succeed. If any specs fail to match, we'll set
     * this to TR_FILTER_NO_MATCH. */
    retval=TR_FILTER_MATCH;
    for (this_fspec = tr_fline_iter_first(fline_iter, this_fline);
         this_fspec != NULL;
         this_fspec = tr_fline_iter_next(fline_iter)) {
      if (!tr_fspec_matches(this_fspec, filt->type, target)) {
        retval=TR_FILTER_NO_MATCH; /* set this in case this is the last filter line */
        break; /* give up on this filter line */
      }
    }

    if (retval==TR_FILTER_MATCH)
      break;

  }

  if (retval==TR_FILTER_MATCH) {
    /* Matched line ii. Grab its action and constraints. */
    *out_action = this_fline->action;
    if (constraints!=NULL) {
      /* if either constraint is missing, these are no-ops */
      tr_constraint_add_to_set(constraints, this_fline->realm_cons);
      tr_constraint_add_to_set(constraints, this_fline->domain_cons);
    }
  }

  return retval;
}

void tr_fspec_free(TR_FSPEC *fspec)
{
  talloc_free(fspec);
}

/**
 * Helper for tr_fspec_destructor - calls tr_free_name on its first argument
 *
 * @param item void pointer to a TR_NAME
 * @param cookie ignored
 */
static void fspec_destruct_helper(void *item, void *cookie)
{
  TR_NAME *name = (TR_NAME *) item;
  tr_free_name(name);
}
static int tr_fspec_destructor(void *obj)
{
  TR_FSPEC *fspec = talloc_get_type_abort(obj, TR_FSPEC);

  if (fspec->field != NULL)
    tr_free_name(fspec->field);

  if (fspec->match)
    tr_list_foreach(fspec->match, fspec_destruct_helper, NULL);

  return 0;
}

TR_FSPEC *tr_fspec_new(TALLOC_CTX *mem_ctx)
{
  TR_FSPEC *fspec = talloc(mem_ctx, TR_FSPEC);

  if (fspec != NULL) {
    fspec->field = NULL;
    fspec->match = tr_list_new(fspec);
    if (fspec->match == NULL) {
      talloc_free(fspec);
      return NULL;
    }
    talloc_set_destructor((void *)fspec, tr_fspec_destructor);
  }
  return fspec;
}

/* Helper function and cookie structure for finding a match. The helper is called
 * for every item in the match list, even after a match is found. If a match is found,
 * match should be pointed to the matching item. If this is not NULL, do not change it
 * because a match has already been found. */
struct fspec_match_cookie { TR_NAME *name; TR_NAME *match;};
static void fspec_match_helper(void *item, void *data)
{
  TR_NAME *this_name = (TR_NAME *) item;
  struct fspec_match_cookie *cookie = (struct fspec_match_cookie *) data;
  if (cookie->match == NULL) {
    if (tr_name_prefix_wildcard_match(cookie->name, this_name))
      cookie->match = this_name;
  }
}
/* returns 1 if the spec matches */
int tr_fspec_matches(TR_FSPEC *fspec, TR_FILTER_TYPE ftype, TR_FILTER_TARGET *target)
{
  struct tr_filter_field_entry *field=NULL;
  struct fspec_match_cookie cookie = {0};

  if (fspec==NULL)
    return 0;

  /* Look up how to handle the requested field */
  field = tr_filter_field_entry(ftype, fspec->field);
  if (field==NULL) {
    tr_err("tr_fspec_matches: No entry to handle field %.*s for %*s filter.",
           fspec->field->len, fspec->field->buf,
           tr_filter_type_to_string(ftype));
    return 0;
  }

  cookie.name = field->get(target);
  if (cookie.name==NULL)
    return 0; /* if there's no value, there's no match */

  cookie.match = NULL;
  tr_list_foreach(fspec->match,
                  fspec_match_helper,
                  &cookie);
  if (cookie.match) {
    tr_debug("tr_fspec_matches: Field %.*s value \"%.*s\" matches \"%.*s\" for %s filter.",
             fspec->field->len, fspec->field->buf,
             cookie.name->len, cookie.name->buf,
             cookie.match->len, cookie.match->buf,
             tr_filter_type_to_string(ftype));
  } else {
        tr_debug("tr_fspec_matches: Field %.*s value \"%.*s\" does not match for %s filter.",
                 fspec->field->len, fspec->field->buf,
                 cookie.name->len, cookie.name->buf,
                 tr_filter_type_to_string(ftype));
  }
  return (cookie.match != NULL);
}

void tr_fline_free(TR_FLINE *fline)
{
  talloc_free(fline);
}

TR_FLINE *tr_fline_new(TALLOC_CTX *mem_ctx)
{
  TR_FLINE *fl = talloc(mem_ctx, TR_FLINE);

  if (fl != NULL) {
    fl->action = TR_FILTER_ACTION_UNKNOWN;
    fl->realm_cons = NULL;
    fl->domain_cons = NULL;
    fl->specs = tr_list_new(fl);
    if (fl->specs == NULL) {
      talloc_free(fl);
      return NULL;
    }
  }
  return fl;
}

TR_FILTER *tr_filter_new(TALLOC_CTX *mem_ctx)
{
  TR_FILTER *f = talloc(mem_ctx, TR_FILTER);

  if (f != NULL) {
    f->type = TR_FILTER_TYPE_UNKNOWN;
    f->lines = tr_list_new(f);
    if (f->lines == NULL) {
      talloc_free(f);
      return NULL;
    }
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
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  TR_FILTER_ITER *filt_iter = tr_filter_iter_new(tmp_ctx);
  TR_FLINE *this_fline = NULL;
  TR_FLINE_ITER *fline_iter = tr_fline_iter_new(tmp_ctx);
  TR_FSPEC *this_fspec = NULL;

  if ((!filt) || (!filt_iter) || (!fline_iter)) {
    talloc_free(tmp_ctx);
    return 0;
  }

  /* check that we recognize the type */
  switch(filt->type) {
    case TR_FILTER_TYPE_TID_INBOUND:
    case TR_FILTER_TYPE_TRP_INBOUND:
    case TR_FILTER_TYPE_TRP_OUTBOUND:
      break;

    default:
      talloc_free(tmp_ctx);
      return 0; /* if we get here, either TR_FILTER_TYPE_UNKNOWN or an invalid value was found */
  }

  for (this_fline = tr_filter_iter_first(filt_iter, filt);
       this_fline != NULL;
       this_fline = tr_filter_iter_next(filt_iter)) {
    /* check that we recognize the action */
    switch(this_fline->action) {
      case TR_FILTER_ACTION_ACCEPT:
      case TR_FILTER_ACTION_REJECT:
        break;

      default:
        /* if we get here, either TR_FILTER_ACTION_UNKNOWN or an invalid value was found */
        talloc_free(tmp_ctx);
        return 0;
    }

    for (this_fspec = tr_fline_iter_first(fline_iter, this_fline);
         this_fspec != NULL;
         this_fspec = tr_fline_iter_next(fline_iter)) {
      if (!tr_filter_validate_spec_field(filt->type, this_fspec)) {
        talloc_free(tmp_ctx);
        return 0;
      }

      /* check that at least one match is defined*/
      if (tr_list_length(this_fspec->match) == 0) {
        talloc_free(tmp_ctx);
        return 0;
      }
    }
  }

  /* We ran the gauntlet. Success! */
  talloc_free(tmp_ctx);
  return 1;
}

int tr_filter_validate_spec_field(TR_FILTER_TYPE ftype, TR_FSPEC *fspec)
{
  if ((fspec==NULL) || (tr_filter_field_entry(ftype, fspec->field)==NULL))
    return 0; /* unknown field */

  return 1;
}

/**
 * Allocate a new filter set.
 *
 * @param mem_ctx Talloc context for the new set
 * @return Pointer to new set, or null on error
 */
TR_FILTER_SET *tr_filter_set_new(TALLOC_CTX *mem_ctx)
{
  TR_FILTER_SET *set=talloc(mem_ctx, TR_FILTER_SET);
  if (set!=NULL) {
    set->next=NULL;
    set->this=NULL;
  }
  return set;
}

/**
 * Free a filter set
 *
 * @param fs Filter set to free
 */
void tr_filter_set_free(TR_FILTER_SET *fs)
{
  talloc_free(fs);
}

/**
 * Find the tail of the filter set linked list.
 *
 * @param set Set to find tail of
 * @return Last element in the list
 */
static TR_FILTER_SET *tr_filter_set_tail(TR_FILTER_SET *set)
{
  while (set->next)
    set=set->next;
  return set;
}

/**
 * Add new filter to filter set.
 *
 * @param set Filter set
 * @param new New filter to add
 * @return 0 on success, nonzero on error
 */
int tr_filter_set_add(TR_FILTER_SET *set, TR_FILTER *new)
{
  TR_FILTER_SET *tail=NULL;

  if (set->this==NULL)
    tail=set;
  else {
    tail=tr_filter_set_tail(set);
    tail->next=tr_filter_set_new(set);
    if (tail->next==NULL)
      return 1;
    tail=tail->next;
  }
  tail->this=new;
  talloc_steal(tail, new);
  return 0;
}

/**
 * Find a filter of a given type in the filter set. If there are multiple, returns the first one.
 *
 * @param set Filter set to search
 * @param type Type of filter to find
 * @return Borrowed pointer to the filter, or null if no filter of that type is found
 */
TR_FILTER *tr_filter_set_get(TR_FILTER_SET *set, TR_FILTER_TYPE type)
{
  TR_FILTER_SET *cur=set;
  while(cur!=NULL) {
    if ((cur->this != NULL) && (cur->this->type == type))
      return cur->this;
    cur=cur->next;
  }
  return NULL;
}

TR_FILTER_TYPE filter_type[]={TR_FILTER_TYPE_TID_INBOUND,
                              TR_FILTER_TYPE_TRP_INBOUND,
                              TR_FILTER_TYPE_TRP_OUTBOUND};
const char *filter_label[]={"tid_inbound",
                            "trp_inbound",
                            "trp_outbound"};
size_t num_filter_types=sizeof(filter_type)/sizeof(filter_type[0]);

const char *tr_filter_type_to_string(TR_FILTER_TYPE ftype)
{
  size_t ii=0;

  for (ii=0; ii<num_filter_types; ii++) {
    if (ftype==filter_type[ii])
      return filter_label[ii];
  }
  return "unknown";
}

TR_FILTER_TYPE tr_filter_type_from_string(const char *s)
{
  size_t ii=0;

  for(ii=0; ii<num_filter_types; ii++) {
    if (0==strcmp(s, filter_label[ii]))
      return filter_type[ii];
  }
  return TR_FILTER_TYPE_UNKNOWN;
}
