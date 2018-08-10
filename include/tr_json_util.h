/*
 * Copyright (c) 2018, JANET(UK)
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

/* Utilities for working with JSON/jansson */

#ifndef TRUST_ROUTER_TR_JSON_UTIL_H
#define TRUST_ROUTER_TR_JSON_UTIL_H

/**
 * @def OBJECT_SET_OR_FAIL(job, key, val)
 * Add a key/value pair to an object or jump to the cleanup label
 * if the value is null.
 *
 * @param jobj JSON object instance to receive the key/value pair
 * @param key key to set
 * @param val value to set
 */
#define OBJECT_SET_OR_FAIL(jobj, key, val)     \
do {                                           \
  if (val)                                     \
    json_object_set_new((jobj),(key),(val));   \
  else                                         \
    goto cleanup;                              \
} while (0)

/**
 * @def OBJECT_SET_OR_SKIP(job, key, val)
 * Add a key/value pair to an object only if it is non-null.
 *
 * @param jobj JSON object instance to receive the key/value pair
 * @param key key to set
 * @param val value to set
 */
#define OBJECT_SET_OR_SKIP(jobj, key, val)     \
do {                                           \
  if (val)                                     \
    json_object_set_new((jobj),(key),(val));   \
} while (0)


/**
 * @def ARRAY_APPEND_OR_FAIL(job, key, val)
 * Append a value to an array or jump to the cleanup label
 * if the value is null.
 *
 * @param jobj JSON array instance to receive the value
 * @param val value to set
 */
#define ARRAY_APPEND_OR_FAIL(jary, val)        \
do {                                           \
  if (val)                                     \
    json_array_append_new((jary),(val));       \
  else                                         \
    goto cleanup;                              \
} while (0)


#endif //TRUST_ROUTER_TR_JSON_UTIL_H
