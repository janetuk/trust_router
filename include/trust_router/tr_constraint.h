/*
 * Copyright (c) 2012, JANET(UK)
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

#ifndef TR_CONSTRAINT_H
#define TR_CONSTRAINT_H

#include <trust_router/tr_name.h>
#include <trust_router/tid.h>

typedef struct tr_constraint TR_CONSTRAINT;

TR_EXPORT TR_CONSTRAINT *tr_constraint_new(TALLOC_CTX *mem_ctx);
TR_EXPORT void tr_constraint_free(TR_CONSTRAINT *cons);
void TR_EXPORT tr_constraint_add_to_set (TR_CONSTRAINT_SET **cs, TR_CONSTRAINT *c);
int TR_EXPORT tr_constraint_set_validate( TR_CONSTRAINT_SET *);
TR_EXPORT TR_CONSTRAINT_SET *tr_constraint_set_filter(TID_REQ *request,
                                                      TR_CONSTRAINT_SET *orig,
                                                      const char * constraint_type);
TR_EXPORT TR_CONSTRAINT_SET *tr_constraint_set_intersect(TID_REQ *request,
                                                         TR_CONSTRAINT_SET *input);
int TR_EXPORT tr_constraint_set_get_match_strings(TID_REQ *,
                                                  TR_CONSTRAINT_SET *,
                                                  const char * constraint_type,
                                                  tr_const_string **output,
                                                  size_t *output_len);

/* This is not meant to be public, but is in the symbol list for Debian */
TR_EXPORT int tr_prefix_wildcard_match(const char *str, const char *wc_str);

#endif
