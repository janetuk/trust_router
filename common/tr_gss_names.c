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

#include <talloc.h>
#include <glib.h>

#include <tr_gss_names.h>
#include <tr_debug.h>

/**
 * Helper for tr_gss_names_destructor - calls tr_free_name on its first argument
 *
 * @param item void pointer to a TR_NAME
 * @param cookie ignored
 */
static void gss_names_destruct_helper(void *item, void *cookie)
{
  TR_NAME *name = (TR_NAME *) item;
  tr_free_name(name);
}
static int tr_gss_names_destructor(void *obj)
{
  TR_GSS_NAMES *gss_names=talloc_get_type_abort(obj, TR_GSS_NAMES);
  if (gss_names->names)
    tr_list_foreach(gss_names->names, gss_names_destruct_helper, NULL);
  return 0;
}
TR_GSS_NAMES *tr_gss_names_new(TALLOC_CTX *mem_ctx)
{
  TR_GSS_NAMES *gn = talloc(mem_ctx, TR_GSS_NAMES);
  if (gn != NULL) {
    gn->names = tr_list_new(gn);
    if (gn->names == NULL) {
      talloc_free(gn);
      return NULL;
    }
    talloc_set_destructor((void *)gn, tr_gss_names_destructor);
  }
  return gn;
}

void tr_gss_names_free(TR_GSS_NAMES *gn)
{
  talloc_free(gn);
}

/* returns 0 on success */
int tr_gss_names_add(TR_GSS_NAMES *gn, TR_NAME *new)
{
  return (NULL == tr_list_add(gn->names, new, 0)); /* nonzero if the add failed */
}

/**
 * Create a duplicate GSS names struct
 *
 * @param mem_ctx
 * @param orig
 * @return
 */
TR_GSS_NAMES *tr_gss_names_dup(TALLOC_CTX *mem_ctx, TR_GSS_NAMES *orig)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  TR_GSS_NAMES *new = tr_gss_names_new(tmp_ctx);
  TR_GSS_NAMES_ITER *iter = tr_gss_names_iter_new(tmp_ctx);
  TR_NAME *this = NULL;

  if ( !orig || !new || !iter ) {
    talloc_free(tmp_ctx);
    return NULL;
  }
  for (this = tr_gss_names_iter_first(iter, orig);
       this != NULL;
       this = tr_gss_names_iter_next(iter)) {
    if (tr_gss_names_add(new, tr_dup_name(this)) != 0) {
      talloc_free(tmp_ctx);
      return NULL;
    }
  }
  /* success */
  talloc_steal(mem_ctx, new);
  return new;
}

int tr_gss_names_matches(TR_GSS_NAMES *gn, TR_NAME *name)
{
  TR_GSS_NAMES_ITER iter={0};
  TR_NAME *this = NULL;

  if ((!gn) || (!name))
    return 0;

  for (this = tr_gss_names_iter_first(&iter, gn);
      this != NULL;
      this = tr_gss_names_iter_next(&iter)) {
    if (tr_name_cmp_case_sensitive(name, this) == 0)
      return 1;
  }
  return 0;
}

json_t *tr_gss_names_to_json_array(TR_GSS_NAMES *gss_names)
{
  TR_GSS_NAMES_ITER *iter = tr_gss_names_iter_new(NULL);
  json_t *jarray = json_array();
  TR_NAME *name = tr_gss_names_iter_first(iter, gss_names);
  while (name) {
    json_array_append_new(jarray, tr_name_to_json_string(name));
    name = tr_gss_names_iter_next(iter);
  }
  tr_gss_names_iter_free(iter);
  return jarray;
}

