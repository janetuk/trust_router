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

#ifndef __TR_GSS_H__
#define __TR_GSS_H__

#include <talloc.h>
#include <tr_list.h>

#include <tr_name_internal.h>

typedef struct tr_gss_names {
  TR_LIST *names;
} TR_GSS_NAMES;

typedef TR_LIST_ITER TR_GSS_NAMES_ITER;

/* Iterator for TR_FILTER lines */
#define tr_gss_names_iter_new(CTX) (tr_list_iter_new(CTX))
#define tr_gss_names_iter_free(ITER) (tr_list_iter_free(ITER))
#define tr_gss_names_iter_first(ITER, GSSN) ((TR_NAME *) tr_list_iter_first((ITER), (GSSN)->names))
#define tr_gss_names_iter_next(ITER) ((TR_NAME *) tr_list_iter_next(ITER))

TR_GSS_NAMES *tr_gss_names_new(TALLOC_CTX *mem_ctx);
void tr_gss_names_free(TR_GSS_NAMES *gn);
int tr_gss_names_add(TR_GSS_NAMES *gn, TR_NAME *new);
TR_GSS_NAMES *tr_gss_names_dup(TALLOC_CTX *mem_ctx, TR_GSS_NAMES *orig);
int tr_gss_names_matches(TR_GSS_NAMES *gn, TR_NAME *name);
#define tr_gss_names_length(GSSN) (tr_list_length((GSSN)->names))
#define tr_gss_names_index(GSSN, INDEX) (tr_list_index((GSSN)->names, (INDEX)))

json_t *tr_gss_names_to_json_array(TR_GSS_NAMES *gss_names);

#endif /* __TR_GSS_H__ */
