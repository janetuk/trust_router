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

#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <dirent.h>

#include <tr_config.h>
#include <tr.h>

void tr_print_config (FILE *stream, TR_CFG *cfg) {
  fprintf(stream, "tr_print_config(): Not yet implemented.\n");
  return;
}

void tr_cfg_free (TR_CFG *cfg) {
  /* TBD */
  return;
}

TR_CFG_RC tr_apply_new_config (TR_INSTANCE *tr) {
  TR_CFG_RC rc = TR_CFG_SUCCESS;

  if (!tr)
    return TR_CFG_BAD_PARAMS;

  tr->active_cfg = tr->new_cfg;
  return rc;
}

TR_CFG_RC tr_parse_config (TR_INSTANCE *tr, json_t *jcfg) {

  if (tr->new_cfg) {
    tr_cfg_free(tr->new_cfg);
    tr->new_cfg = NULL;
  }

  //  if ((TR_CFG_SUCCESS != tr_cfg_parse_internal(tr, jcfg)) ||
  //      (TR_CFG_SUCCESS != tr_cfg_parse_rp_realms(tr, jcfg)) ||
  //      (TR_CFG_SUCCESS != tr_cfg_parse_idp_realms(tr, jcfg)) ||
  //      (TR_CFG_SUCCESS != tr_cfg_parse_comms(tr, jcfg))) {
  //    if (tr->new_cfg)
  //      tr_cfg_free(tr->new_cfg);
  //    return TR_CFG_ERROR;
  //  }
  return TR_CFG_SUCCESS;
}

json_t *tr_read_config (int n, struct dirent **cfg_files) {
  json_t *jcfg = NULL;
  json_t *temp = NULL;
  json_error_t err;

  if (!cfg_files)
    return NULL;

  while (n--) {
    fprintf(stderr, "tr_read_config: Parsing %s.\n", cfg_files[n]->d_name);
    if (NULL == (temp = json_load_file(cfg_files[n]->d_name, JSON_DISABLE_EOF_CHECK, &err))) {
      fprintf (stderr, "tr_read_config: Error parsing config file %s.\n", cfg_files[n]->d_name);
      return NULL;
    }

    if (!jcfg) {
      jcfg = temp;
    }else {
      if (-1 == json_object_update(jcfg, temp)) {
	fprintf(stderr, "tr_read_config: Error merging config information.\n");
	return NULL;
      }
    }
  }

  fprintf(stderr, "tr_read_config: Merged configuration complete:\n%s\n", json_dumps(jcfg, 0));

  return jcfg;
}

static int is_cfg_file(const struct dirent *dent) {
  int n;

  /* if the last four letters of the filename are .cfg, return true. */
  if ((4 <= (n = strlen(dent->d_name))) &&
      (0 == strcmp(&(dent->d_name[n-4]), ".cfg"))) {
    return 1;
  }

  /* otherwise, return false. */
  return 0;
}

int tr_find_config_files (struct dirent ***cfg_files) {
  int n = 0, i = 0;
  
  n = scandir(".", cfg_files, &is_cfg_file, 0);

  if (n < 0) {
    perror("scandir");
    fprintf(stderr, "tr_find_config(): scandir error.\n");
    return 0;
  }

  if (n == 0) {
    fprintf (stderr, "tr_find_config(): No config files found.\n");
    return 0;
  }

  i = n;
  while(i--) {
    fprintf(stderr, "tr_find_config(): Config file found (%s).\n", (*cfg_files)[i]->d_name);
  }
    
  return n;
}
