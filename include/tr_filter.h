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

#ifndef TR_FILTER_H
#define TR_FILTER_H

#include <talloc.h>
#include <jansson.h>
#include <glib.h>

#include <tr_list.h>
#include <tr_name_internal.h>
#include <trust_router/tr_constraint.h>
#include <trust_router/tid.h>
#include <trust_router/trp.h>

/* Filter actions */
typedef enum tr_filter_action {
  TR_FILTER_ACTION_REJECT = 0,
  TR_FILTER_ACTION_ACCEPT,
  TR_FILTER_ACTION_UNKNOWN
} TR_FILTER_ACTION;

/* Match codes */
#define TR_FILTER_MATCH 0
#define TR_FILTER_NO_MATCH 1

/* Filter types */
typedef enum {
  TR_FILTER_TYPE_TID_INBOUND = 0,
  TR_FILTER_TYPE_TRP_INBOUND,
  TR_FILTER_TYPE_TRP_OUTBOUND,
  TR_FILTER_TYPE_UNKNOWN
} TR_FILTER_TYPE;

typedef struct tr_fspec {
  TR_NAME *field;
  TR_LIST *match;
} TR_FSPEC;

typedef struct tr_fline {
  TR_FILTER_ACTION action;
  GPtrArray *specs;
  TR_CONSTRAINT *realm_cons;
  TR_CONSTRAINT *domain_cons;
} TR_FLINE;

typedef struct tr_fline_iter {
  TR_FLINE *fline;
  guint ii;
} TR_FLINE_ITER;

typedef struct tr_filter {
  TR_FILTER_TYPE type;
  TR_LIST *lines;
} TR_FILTER;

typedef struct tr_filter_set TR_FILTER_SET;
struct tr_filter_set {
  TR_FILTER *this;
  TR_FILTER_SET *next;
};

/**
 * Structure to hold information needed to filter different targets.
 */
typedef struct tr_filter_target {
  /* An inforec also needs realm and community information */
  TRP_INFOREC *trp_inforec;
  TRP_UPD *trp_upd;

  /* a TID request has all the data it needs to be filtered */
  TID_REQ *tid_req;
} TR_FILTER_TARGET;

TR_FILTER_SET *tr_filter_set_new(TALLOC_CTX *mem_ctx);
void tr_filter_set_free(TR_FILTER_SET *fs);
int tr_filter_set_add(TR_FILTER_SET *set, TR_FILTER *new);
TR_FILTER *tr_filter_set_get(TR_FILTER_SET *set, TR_FILTER_TYPE type);

TR_FILTER *tr_filter_new(TALLOC_CTX *mem_ctx);
void tr_filter_free(TR_FILTER *filt);

void tr_filter_set_type(TR_FILTER *filt, TR_FILTER_TYPE type);
TR_FILTER_TYPE tr_filter_get_type(TR_FILTER *filt);
TR_FLINE *tr_filter_add_line(TR_FILTER *filt, TR_FLINE *line);

TR_FLINE *tr_fline_new(TALLOC_CTX *mem_ctx);
void tr_fline_free(TR_FLINE *fline);
TR_FSPEC *tr_fline_add_spec(TR_FLINE *fline, TR_FSPEC *spec);

TR_FSPEC *tr_fspec_new(TALLOC_CTX *mem_ctx);
void tr_fspec_free(TR_FSPEC *fspec);
TR_NAME *tr_fspec_add_match(TR_FSPEC *fspec, TR_NAME *match);

int tr_fspec_matches(TR_FSPEC *fspec, TR_FILTER_TYPE ftype, TR_FILTER_TARGET *target);

/* Iterator for TR_FILTER.lines */
typedef TR_LIST_ITER TR_FILTER_ITER;
#define tr_filter_iter_new(CTX) (tr_list_iter_new(CTX))
#define tr_filter_iter_free(ITER) (tr_list_iter_free(ITER))
#define tr_filter_iter_first(ITER, FILT) ((TR_FLINE *) tr_list_iter_first((ITER), (FILT)->lines))
#define tr_filter_iter_next(ITER) ((TR_FLINE *) tr_list_iter_next(ITER))
#define tr_filter_add_line(FILT, LINE) ((TR_FLINE *) tr_list_add((FILT)->lines, (LINE), 1))

TR_FLINE_ITER *tr_fline_iter_new(TALLOC_CTX *mem_ctx);
void tr_fline_iter_free(TR_FLINE_ITER *iter);
TR_FSPEC * tr_fline_iter_first(TR_FLINE_ITER *iter, TR_FLINE *fline);
TR_FSPEC * tr_fline_iter_next(TR_FLINE_ITER *iter);

/* Iterator for TR_FSPEC matches */
typedef TR_LIST_ITER TR_FSPEC_ITER;
#define tr_fspec_iter_new(CTX) (tr_list_iter_new(CTX))
#define tr_fspec_iter_free(ITER) (tr_list_iter_free(ITER))
#define tr_fspec_iter_first(ITER, SPEC) (tr_list_iter_first((ITER), (SPEC)->match))
#define tr_fspec_iter_next(ITER) (tr_list_iter_next(ITER))
#define tr_fspec_add_match(SPEC, MATCH) ((TR_NAME *) tr_list_add((SPEC)->match, (MATCH), 0))

/*In tr_constraint.c and exported, but not really a public symbol; needed by tr_filter.c and by tr_constraint.c*/
int TR_EXPORT tr_prefix_wildcard_match(const char *str, const char *wc_str);

int tr_filter_apply(TR_FILTER_TARGET *target, TR_FILTER *filt, TR_CONSTRAINT_SET **constraints, TR_FILTER_ACTION *out_action);
void tr_filter_target_free(TR_FILTER_TARGET *target);
TR_FILTER_TARGET *tr_filter_target_tid_req(TALLOC_CTX *mem_ctx, TID_REQ *req);
TR_FILTER_TARGET *tr_filter_target_trp_inforec(TALLOC_CTX *mem_ctx, TRP_UPD *upd, TRP_INFOREC *inforec);

TR_CONSTRAINT_SET *tr_constraint_set_from_fline(TR_FLINE *fline);

int tr_filter_validate(TR_FILTER *filt);
int tr_filter_validate_spec_field(TR_FILTER_TYPE ftype, TR_FSPEC *fspec);
const char *tr_filter_type_to_string(TR_FILTER_TYPE ftype);
TR_FILTER_TYPE tr_filter_type_from_string(const char *s);

/* tr_filter_encoders.c */
json_t *tr_filter_set_to_json(TR_FILTER_SET *filter_set);

#endif
