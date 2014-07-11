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

#include <jansson.h>
#include "jansson_iterators.h"
#include <stdio.h>
#include <assert.h>

#include <trust_router/tid.h>
#include <trust_router/tr_constraint.h>
#include <tr_debug.h>

static TID_REQ *request = NULL;

static int handle_test_case(
			     json_t *tc)
{
  json_t *constraints, *valid, *expected;
  int validp;
  json_t *result;
  assert(constraints = json_object_get(tc, "constraints"));
  assert( valid = json_object_get(tc, "valid"));
  validp = tr_constraint_set_validate((TR_CONSTRAINT_SET *)constraints);
  if (validp != json_is_true(valid)) {
    tr_debug("Unexpected validation result for \n");
    json_dumpf( constraints, stderr, JSON_INDENT(4));
    return 0;
  }
  if (!validp)
    return 1;
  assert( expected = json_object_get(tc, "expected"));
  result = (json_t *) tr_constraint_set_intersect(request, (TR_CONSTRAINT_SET *) constraints);
  if (!json_equal(result, expected)) {
    tr_debug("Unexpected intersection; actual:\n");
    json_dumpf(result, stderr, JSON_INDENT(4));
    tr_debug("Expected: \n");
    json_dumpf(expected, stderr, JSON_INDENT(4));
    return 0;
  }
  return 1;
}

int main(void) {
  json_t *tests;
  int error=0;
  json_t *tc;
  size_t index;
  request = tid_req_new();
  tests = json_load_file(TESTS, JSON_REJECT_DUPLICATES|JSON_DISABLE_EOF_CHECK, NULL);
  json_array_foreach(tests, index, tc)
    if (!handle_test_case(tc))
      error = 1;
  if (error)
    return 1;
  return 0;
}
