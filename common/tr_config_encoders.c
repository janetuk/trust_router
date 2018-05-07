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

#include <jansson.h>
#include <tr_config.h>
#include <tr_json_util.h>

static json_t *tr_cfg_file_to_json(TR_CFG_FILE *cfg_file)
{
  json_t *file_json = NULL;
  json_t *retval = NULL;

  file_json = json_object();
  if (file_json == NULL)
    goto cleanup;

  OBJECT_SET_OR_FAIL(file_json, "name", json_string(cfg_file->name));
  if (cfg_file->serial != TR_CFG_INVALID_SERIAL)
    OBJECT_SET_OR_FAIL(file_json, "serial", json_integer(cfg_file->serial));

  /* succeeded - set the return value and increment the reference count */
  retval = file_json;
  json_incref(retval);

cleanup:
  if (file_json)
    json_decref(file_json);

  return retval;
}

json_t *tr_cfg_files_to_json_array(TR_CFG *cfg)
{
  guint ii;
  json_t *jarray = json_array();
  json_t *retval = NULL;

  if (jarray == NULL)
    goto cleanup;

  for (ii=0; ii<cfg->files->len; ii++) {
    ARRAY_APPEND_OR_FAIL(jarray,
                         tr_cfg_file_to_json(
                             &g_array_index(cfg->files, TR_CFG_FILE, ii)));
  }

  /* success */
  retval = jarray;
  json_incref(retval);

cleanup:
  if (jarray)
    json_decref(jarray);

  return retval;
}
