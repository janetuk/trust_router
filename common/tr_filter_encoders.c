/*
 * Copyright (c) 2018 JANET(UK)
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
#include <jansson.h>

#include <tr_filter.h>
#include <tr_constraint_internal.h>

/* helper for below */
#define OBJECT_SET_OR_FAIL(jobj, key, val)     \
do {                                           \
  if (val)                                     \
    json_object_set_new((jobj),(key),(val));   \
  else                                         \
    goto cleanup;                              \
} while (0)

#define ARRAY_APPEND_OR_FAIL(jary, val)        \
do {                                           \
  if (val)                                     \
    json_array_append_new((jary),(val));       \
  else                                         \
    goto cleanup;                              \
} while (0)


typedef json_t *(ITEM_ENCODER_FUNC)(void *);

enum array_type {
  ARRAY_TYPE_FSPEC,
  ARRAY_TYPE_CONSTRAINT
};
/**
 * Make an array of matches from a TR_FSPEC or TR_CONSTRAINT
 *
 * @param obj
 * @param type
 * @return
 */
static json_t *tr_names_to_json_array(void *obj, enum array_type type)
{
  json_t *jarray = json_array();
  json_t *retval = NULL;
  TR_FSPEC_ITER fspec_iter = {0};
  TR_CONSTRAINT_ITER cons_iter = {0};
  TR_NAME *this_match = NULL;

  if (jarray == NULL)
    goto cleanup;

  switch(type) {
    case ARRAY_TYPE_FSPEC:
      this_match = tr_fspec_iter_first(&fspec_iter, (TR_FSPEC *)obj);
      break;

    case ARRAY_TYPE_CONSTRAINT:
      this_match = tr_constraint_iter_first(&cons_iter, (TR_CONSTRAINT *)obj);
      break;
  }
  while(this_match) {
    ARRAY_APPEND_OR_FAIL(jarray, tr_name_to_json_string(this_match));
    switch(type) {
      case ARRAY_TYPE_FSPEC:
        this_match = tr_fspec_iter_next(&fspec_iter);
        break;

      case ARRAY_TYPE_CONSTRAINT:
        this_match = tr_constraint_iter_next(&cons_iter);
        break;
    }
  }
  /* success */
  retval = jarray;
  json_incref(retval);

cleanup:
  if (jarray)
    json_decref(jarray);

  return retval;
}

static json_t *tr_fspec_to_json(TR_FSPEC *fspec)
{
  json_t *fspec_json = NULL;
  json_t *retval = NULL;

  fspec_json = json_object();
  if (fspec_json == NULL)
    goto cleanup;

  OBJECT_SET_OR_FAIL(fspec_json, "field",
                     tr_name_to_json_string(fspec->field));
  OBJECT_SET_OR_FAIL(fspec_json, "matches",
                     tr_names_to_json_array(fspec, ARRAY_TYPE_FSPEC));

  /* succeeded - set the return value and increment the reference count */
  retval = fspec_json;
  json_incref(retval);

cleanup:
  if (fspec_json)
    json_decref(fspec_json);
  return retval;
}

static json_t *tr_fspecs_to_json_array(TR_FLINE *fline)
{
  json_t *jarray = json_array();
  json_t *retval = NULL;
  TR_FLINE_ITER *iter = tr_fline_iter_new(NULL);
  TR_FSPEC *this_fspec = NULL;

  if ((jarray == NULL) || (iter == NULL))
    goto cleanup;

  for (this_fspec = tr_fline_iter_first(iter, fline);
       this_fspec != NULL;
       this_fspec = tr_fline_iter_next(iter)) {
    ARRAY_APPEND_OR_FAIL(jarray, tr_fspec_to_json(this_fspec));
  }
  /* success */
  retval = jarray;
  json_incref(retval);

cleanup:
  if (jarray)
    json_decref(jarray);
  if (iter)
    tr_fline_iter_free(iter);

  return retval;
}

static json_t *tr_fline_to_json(TR_FLINE *fline)
{
  json_t *fline_json = NULL;
  json_t *retval = NULL;

  fline_json = json_object();
  if (fline_json == NULL)
    goto cleanup;

  OBJECT_SET_OR_FAIL(fline_json, "action",
                     json_string( (fline->action == TR_FILTER_ACTION_ACCEPT) ? "accept" : "reject"));
  OBJECT_SET_OR_FAIL(fline_json, "specs",
                     tr_fspecs_to_json_array(fline));
  if (fline->realm_cons) {
    OBJECT_SET_OR_FAIL(fline_json, "realm_constraints",
                       tr_names_to_json_array(fline->realm_cons, ARRAY_TYPE_CONSTRAINT));
  }
  if (fline->domain_cons) {
    OBJECT_SET_OR_FAIL(fline_json, "domain_constraints",
                       tr_names_to_json_array(fline->domain_cons, ARRAY_TYPE_CONSTRAINT));
  }

  /* succeeded - set the return value and increment the reference count */
  retval = fline_json;
  json_incref(retval);

cleanup:
  if (fline_json)
    json_decref(fline_json);
  return retval;
}

static json_t *tr_flines_to_json_array(TR_FILTER *filt)
{
  json_t *jarray = json_array();
  json_t *retval = NULL;
  TR_FILTER_ITER *iter = tr_filter_iter_new(NULL);
  TR_FLINE *this_fline = NULL;

  if ((jarray == NULL) || (iter == NULL))
    goto cleanup;

  for(this_fline = tr_filter_iter_first(iter, filt);
      this_fline != NULL;
      this_fline = tr_filter_iter_next(iter)) {
    ARRAY_APPEND_OR_FAIL(jarray, tr_fline_to_json(this_fline));
  }
  /* success */
  retval = jarray;
  json_incref(retval);

cleanup:
  if (jarray)
    json_decref(jarray);
  if (iter)
    tr_filter_iter_free(iter);

  return retval;
}
json_t *tr_filter_set_to_json(TR_FILTER_SET *filter_set)
{
  json_t *fset_json = NULL;
  json_t *retval = NULL;
  TR_FILTER *filt = NULL;
  TR_FILTER_TYPE *filt_type = NULL;
  TR_FILTER_TYPE types[] = {
      TR_FILTER_TYPE_TID_INBOUND,
      TR_FILTER_TYPE_TRP_INBOUND,
      TR_FILTER_TYPE_TRP_OUTBOUND,
      TR_FILTER_TYPE_UNKNOWN /* list terminator */
  };

  fset_json = json_object();
  if (fset_json == NULL)
    goto cleanup;

  for (filt_type = types; *filt_type != TR_FILTER_TYPE_UNKNOWN; filt_type++) {
    filt = tr_filter_set_get(filter_set, *filt_type);
    if (filt) {
      OBJECT_SET_OR_FAIL(fset_json, tr_filter_type_to_string(*filt_type),
                         tr_flines_to_json_array(filt));
    }
  }

  /* succeeded - set the return value and increment the reference count */
  retval = fset_json;
  json_incref(retval);

cleanup:
  if (fset_json)
    json_decref(fset_json);
  return retval;
}

