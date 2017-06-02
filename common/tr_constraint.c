/*
 * Copyright (c) 2012-2014, JANET(UK)
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
#include "jansson_iterators.h"
#include <assert.h>
#include <talloc.h>

#include <tr_filter.h>
#include <tr_debug.h>

#include <trust_router/tr_constraint.h>
#include <tid_internal.h>


static int tr_constraint_destructor(void *obj)
{
  TR_CONSTRAINT *cons = talloc_get_type_abort(obj, TR_CONSTRAINT);
  int ii = 0;

  if (cons->type != NULL)
    tr_free_name(cons->type);
  for (ii = 0; ii < TR_MAX_CONST_MATCHES; ii++) {
    if (cons->matches[ii] != NULL)
      tr_free_name(cons->matches[ii]);
  }
  return 0;
}

TR_CONSTRAINT *tr_constraint_new(TALLOC_CTX *mem_ctx)
{
  TR_CONSTRAINT *cons = talloc(mem_ctx, TR_CONSTRAINT);
  int ii = 0;

  if (cons != NULL) {
    cons->type = NULL;
    for (ii = 0; ii < TR_MAX_CONST_MATCHES; ii++)
      cons->matches[ii] = NULL;
    talloc_set_destructor((void *) cons, tr_constraint_destructor);
  }
  return cons;
}

void tr_constraint_free(TR_CONSTRAINT *cons)
{
  talloc_free(cons);
}

TR_CONSTRAINT *tr_constraint_dup(TALLOC_CTX *mem_ctx, TR_CONSTRAINT *cons)
{
  TALLOC_CTX *tmp_ctx = NULL;
  TR_CONSTRAINT *new = NULL;
  int ii = 0;

  if (cons == NULL)
    return NULL;

  tmp_ctx = talloc_new(NULL);
  new = tr_constraint_new(tmp_ctx);

  if (new != NULL) {
    new->type = tr_dup_name(cons->type);
    for (ii = 0; ii < TR_MAX_CONST_MATCHES; ii++)
      new->matches[ii] = tr_dup_name(cons->matches[ii]);
    talloc_steal(mem_ctx, new);
  }

  talloc_free(tmp_ctx);
  return new;
}

/* Returns TRUE (1) if the the string (str) matches the wildcard string (wc_str), FALSE (0) if not.
 * Allows for a single '*' as the wildcard character if it is the first character. Leading white
 * space is significant.
 */
int tr_prefix_wildcard_match(const char *str, const char *wc_str)
{
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
  } else if (len != wc_len)
    return 0;


  if (wc_len > len)
    return 0;

  if (0 == strcmp(&(str[len - wc_len]), wc_post)) {
    return 1;
  } else
    return 0;
}

/* This combines the two constraints in a filter line (TR_FLINE) into a single
 * set with two constraints. */
TR_CONSTRAINT_SET *tr_constraint_set_from_fline(TR_FLINE *fline)
{
  json_t *cset = NULL;

  if (!fline)
    return NULL;

  if (fline->realm_cons)
    tr_constraint_add_to_set((TR_CONSTRAINT_SET **) &cset, fline->realm_cons);
  if (fline->domain_cons)
    tr_constraint_add_to_set((TR_CONSTRAINT_SET **) &cset, fline->domain_cons);

  return (TR_CONSTRAINT_SET *) cset;
}

/* A constraint set is represented in json as an array of constraint
 * objects.  So, a constraint set (cset) that consists of one realm
 * constraint and one domain constraint might look like:
 *
 *	{cset: [{domain: [a.com, b.co.uk]},
 *	        {realm: [c.net, d.org]}]}
 *
 * This routine takes a TR_CONSTRAINT, converts it to its JSON representation,
 * and adds that to the TR_CONSTRAINT_SET.
 */
void tr_constraint_add_to_set(TR_CONSTRAINT_SET **cset, TR_CONSTRAINT *cons)
{
  json_t *jcons = NULL;
  json_t *jmatches = NULL;
  int i = 0;

  if ((!cset) || (!cons))
    return;

  /* If we don't already have a json object, create one */
  if (!(*cset))
    *cset = (TR_CONSTRAINT_SET *) json_array();

  /* Create a json object representing cons */
  jmatches = json_array();
  jcons = json_object();

  for (i = 0; ((i < TR_MAX_CONST_MATCHES) && (NULL != cons->matches[i])); i++) {
    json_array_append_new(jmatches, json_string(cons->matches[i]->buf));
  }

  json_object_set_new(jcons, cons->type->buf, jmatches);

  /* Add the created object to the cset object */
  json_array_append_new((json_t *) *cset, jcons);
}

/* Test whether a JSON object has a valid structure
 * to represent a constraint set.
 */
int tr_constraint_set_validate(TR_CONSTRAINT_SET *cset) {
  json_t *json = (json_t *) cset;
  size_t i;
  json_t *set_member;
  if (!json_is_array(json)) {
    tr_debug("Constraint_set is not an array");
    return 0;
  }
  json_array_foreach(json, i, set_member) {
    json_t *value;
    const char *key;
    if (!json_is_object(set_member)) {
      tr_debug("Constraint member at %zu is not an object\n", i);
      return 0;
    }
    json_object_foreach(set_member, key, value) {
      size_t inner_index;
      json_t *inner_value;
      if (!json_is_array(value)) {
        tr_debug("Constraint type %s at index %zu in constraint set is not an array\n", key,
                 i);
        return 0;
      }
      json_array_foreach(value, inner_index, inner_value) {
        if (!json_is_string(inner_value)) {
          tr_debug("Constraint type %s at index %zu in constraint set has non-string element %zu\n",
                   key, i, inner_index);
          return 0;
        }
      }
    }
  }
  return 1;
}


/**
 * Create a new constraint set containing all constraints from #orig
 * with constraint_type #constraint_type and no others.  This constraint set is
 * live until #request is freed.
 */
TR_CONSTRAINT_SET *tr_constraint_set_filter(TID_REQ *request,
                                            TR_CONSTRAINT_SET *orig,
                                            const char *constraint_type)
{
  json_t *orig_cset = (json_t *) orig;
  json_t *new_cs = NULL;
  size_t index;
  json_t *set_member;
  if (!tr_constraint_set_validate((TR_CONSTRAINT_SET *) orig_cset)) {
    tr_debug ("tr_constraint_set_filter: not a valid constraint set\n");
    return NULL;
  }
  assert (new_cs = json_array());
  json_array_foreach(orig_cset, index, set_member) {
    if (json_object_get(set_member, constraint_type))
      json_array_append(new_cs, set_member);
  }
  tid_req_cleanup_json(request, new_cs);
  return (TR_CONSTRAINT_SET *) new_cs;
}

/**
 * Within a given constraint object merge any overlapping domain or
 * realm constraints.  For example ['*','*.net'] can be simplified to
 * ['*']
 */
static void merge_constraints(json_t *constraint, const char *key)
{
  json_t *value_1, *value_2, *constraint_array;
  size_t index_1, index_2;
  /*
   * Go through the loop pairwise linear, removing elements where one
   * element is a subset of the other.  Always shrik the array from
   * the end so that index_1 never becomes invalid (swapping if
   * needed).
   */
  constraint_array = json_object_get(constraint, key);
  if (NULL == constraint_array)
    return;
  json_array_foreach(constraint_array, index_1, value_1)json_array_foreach(constraint_array, index_2, value_2) {
      if (index_2 <= index_1)
        continue;
      if (tr_prefix_wildcard_match(json_string_value(value_2),
                                   json_string_value(value_1))) {
        json_array_remove(constraint_array, index_2);
        index_2--;
      } else if (tr_prefix_wildcard_match(json_string_value(value_1),
                                          json_string_value(value_2))) {
        json_array_set(constraint_array, index_1, value_2);
        json_array_remove(constraint_array, index_2);
        index_2--;
      }
    }
}

/**
 * Returns an array of constraint strings that is the intersection of
 * all constraints in the constraint_set of type #type
 */
static json_t *constraint_intersect_internal(TR_CONSTRAINT_SET *constraints,
                                             const char *constraint_type)
{
  json_t *constraint, *result = NULL;
  size_t i;
  json_array_foreach((json_t *) constraints, i, constraint) {
    merge_constraints(constraint, constraint_type);
    if (NULL == result) {
      result = json_object_get(constraint, constraint_type);
      if (NULL != result)
        result = json_copy(result);
    } else {
      json_t *intersect, *value_1, *value_2;
      size_t index_1, index_2;
      intersect = json_object_get(constraint, constraint_type);
      /*If an element of the constraint set doesn't have a particular
       * constraint type, we ignore that element of the constraint set.
       * However, if no element of the constraint set has a particular
       *     constraint type we return empty (no access) rather than universal
       * access.*/
      if (!intersect)
        continue;
      result_loop:
      json_array_foreach(result, index_1, value_1) {
        json_array_foreach(intersect, index_2, value_2) {
          if (tr_prefix_wildcard_match(json_string_value(value_1),
                                       json_string_value(value_2)))
            goto result_acceptable;
          else if (tr_prefix_wildcard_match(json_string_value(value_2),
                                            json_string_value(value_1))) {
            json_array_set(result, index_1, value_2);
            goto result_acceptable;
          }
        }
        json_array_remove(result, index_1);
        if (index_1 == 0)
          goto result_loop;
        index_1--;
        result_acceptable:
        continue;
      }
    }
  }
  return result;
}

/**
 * Return the intersection of domain and realm constraints.
 * Return is live until #request is freed.
 */
TR_CONSTRAINT_SET *tr_constraint_set_intersect(TID_REQ *request,
                                               TR_CONSTRAINT_SET *input)
{
  json_t *domain = NULL, *realm = NULL;
  json_t *result = NULL, *result_array = NULL;
  if (tr_constraint_set_validate(input)) {
    domain = constraint_intersect_internal(input, "domain");
    realm = constraint_intersect_internal(input, "realm");
  }
  assert(result = json_object());
  if (domain)
    json_object_set_new(result, "domain", domain);
  if (realm)
    json_object_set_new(result, "realm", realm);
  assert(result_array = json_array());
  json_array_append_new(result_array, result);
  tid_req_cleanup_json(request, result_array);
  return (TR_CONSTRAINT_SET *) result_array;
}

/** Get the set of wildcard strings that matches a fully intersected
 * constraint set.  Requires that the constraint set only have one
 * constraint in it, but the constraint may have multiple matches for
 * a given type.  Returns true on success false on failure.  The
 * output is live as long as the request is live.
 */
int tr_constraint_set_get_match_strings(TID_REQ *request,
                                        TR_CONSTRAINT_SET *constraints,
                                        const char *constraint_type,
                                        tr_const_string **output,
                                        size_t *output_len)
{
  json_t *cset = (json_t *) constraints;
  json_t *member, *matches, *value;;
  size_t index, array_size;
  assert (output && output_len);
  *output = NULL;
  *output_len = 0;
  if (json_array_size(cset) != 1) {
    tr_debug("Constraint set for get_match_strings has more than one member\n");
    return -1;
  }
  member = json_array_get(cset, 0);
  matches = json_object_get(member, constraint_type);
  if (!matches)
    return -1;
  array_size = json_array_size(matches);
  if (array_size == 0)
    return -1;
  *output = talloc_array_ptrtype(request, *output, array_size);
  json_array_foreach(matches, index, value)(*output)[index] = json_string_value(value);
  *output_len = array_size;
  return 0;
}
