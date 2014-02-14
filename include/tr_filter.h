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

#include <trust_router/tr_name.h>
#include <tr_constraint.h>
#include <jansson.h>

#define TR_MAX_FILTERS	5
#define TR_MAX_FILTER_LINES 8
#define TR_MAX_FILTER_SPECS 8

/* Filter actions */
#define TR_FILTER_ACTION_REJECT 0
#define TR_FILTER_ACTION_ACCEPT 1

/* Match codes */
#define TR_FILTER_MATCH 0
#define TR_FILTER_NO_MATCH 1

/* Filter types */
#define TR_FILTER_TYPE_RP_PERMITTED 0
/* Other types TBD */

typedef struct tr_fspec {
  TR_NAME *field;
  TR_NAME *match;
} TR_FSPEC;

typedef struct tr_fline {
  int action;
  TR_FSPEC *specs[TR_MAX_FILTER_SPECS];
  TR_CONSTRAINT *realm_cons;
  TR_CONSTRAINT *domain_cons;
} TR_FLINE;
  
typedef struct tr_filter {
  int type;
  TR_FLINE *lines[TR_MAX_FILTER_LINES];
} TR_FILTER;

void tr_filter_free (TR_FILTER *filt);
int tr_prefix_wildcard_match (char *str, char *wc_str);
int tr_filter_process_rp_permitted (TR_NAME *rp_realm, TR_FILTER *rpp_filter, TR_CONSTRAINT_SET *in_constraints, TR_CONSTRAINT_SET **out_constraints, int *out_action);
#endif
