/*
 * Copyright (c) 2012-2018, JANET(UK)
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
#include <talloc.h>

#include <tr_cfgwatch.h>
#include <tr_comm.h>
#include <tr_config.h>
#include <tr_gss_names.h>
#include <tr_debug.h>
#include <tr_filter.h>
#include <trust_router/tr_constraint.h>
#include <tr_idp.h>
#include <tr.h>
#include <trust_router/trp.h>

#if JANSSON_VERSION_HEX < 0x020500
#include "jansson_iterators.h"
#endif

void tr_print_config (TR_CFG *cfg) {
  tr_notice("tr_print_config: Logging running trust router configuration.");
  tr_print_comms(cfg->ctable);
}

void tr_print_comms (TR_COMM_TABLE *ctab)
{
  TR_COMM *comm = NULL;

  for (comm = ctab->comms; NULL != comm; comm = comm->next) {
    tr_notice("tr_print_config: Community %s:", comm->id->buf);

    tr_notice("tr_print_config:  - Member IdPs:");
    tr_print_comm_idps(ctab, comm);

    tr_notice("tr_print_config:  - Member RPs:");
    tr_print_comm_rps(ctab, comm);
  }
}

void tr_print_comm_idps(TR_COMM_TABLE *ctab, TR_COMM *comm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM_ITER *iter=NULL;
  TR_IDP_REALM *idp = NULL;
  char *s=NULL;

  iter=tr_comm_iter_new(tmp_ctx);
  if (iter==NULL) {
    tr_notice("tr_print_config: unable to allocate IdP iterator.");
    talloc_free(tmp_ctx);
    return;
  }
  
  for (idp=tr_idp_realm_iter_first(iter, ctab, tr_comm_get_id(comm));
       NULL!=idp;
       idp=tr_idp_realm_iter_next(iter)) {
    s=tr_idp_realm_to_str(tmp_ctx, idp);
    if (s!=NULL)
      tr_notice("tr_print_config:    - @%s", s);
    else
      tr_notice("tr_print_config: unable to allocate IdP output string.");
  }
  talloc_free(tmp_ctx);
}

void tr_print_comm_rps(TR_COMM_TABLE *ctab, TR_COMM *comm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM_ITER *iter=NULL;
  TR_RP_REALM *rp = NULL;
  char *s=NULL;

  iter=tr_comm_iter_new(tmp_ctx);
  if (iter==NULL) {
    tr_notice("tr_print_config: unable to allocate RP iterator.");
    talloc_free(tmp_ctx);
    return;
  }
  
  for (rp=tr_rp_realm_iter_first(iter, ctab, tr_comm_get_id(comm));
       NULL!=rp;
       rp=tr_rp_realm_iter_next(iter)) {
    s=tr_rp_realm_to_str(tmp_ctx, rp);
    if (s!=NULL)
      tr_notice("tr_print_config:    - @%s", s);
    else
      tr_notice("tr_print_config: unable to allocate RP output string.");
  }
  talloc_free(tmp_ctx);
}

static int tr_cfg_destructor(void *object)
{
  TR_CFG *cfg = talloc_get_type_abort(object, TR_CFG);
  if (cfg->files)
    g_array_unref(cfg->files);
  return 0;
}
TR_CFG *tr_cfg_new(TALLOC_CTX *mem_ctx)
{
  TR_CFG *cfg=talloc(mem_ctx, TR_CFG);
  if (cfg!=NULL) {
    cfg->internal=NULL;
    cfg->rp_clients=NULL;
    cfg->peers=NULL;
    cfg->default_servers=NULL;
    cfg->ctable=tr_comm_table_new(cfg);
    if (cfg->ctable==NULL) {
      talloc_free(cfg);
      return NULL;
    }
    cfg->files = g_array_new(FALSE, FALSE, sizeof(TR_CFG_FILE));
    if (cfg->files == NULL) {
      talloc_free(cfg);
      return NULL;
    }
    talloc_set_destructor((void *)cfg, tr_cfg_destructor);
  }
  return cfg;
}

void tr_cfg_free (TR_CFG *cfg)
{
  talloc_free(cfg);
}

TR_CFG_MGR *tr_cfg_mgr_new(TALLOC_CTX *mem_ctx)
{
  return talloc_zero(mem_ctx, TR_CFG_MGR);
}

void tr_cfg_mgr_free (TR_CFG_MGR *cfg_mgr) {
  talloc_free(cfg_mgr);
}

TR_CFG_RC tr_apply_new_config (TR_CFG_MGR *cfg_mgr)
{
  /* cfg_mgr->active is allowed to be null, but new cannot be */
  if ((cfg_mgr==NULL) || (cfg_mgr->new==NULL))
    return TR_CFG_BAD_PARAMS;

  if (cfg_mgr->active != NULL)
    tr_cfg_free(cfg_mgr->active);

  cfg_mgr->active = cfg_mgr->new;
  cfg_mgr->new=NULL; /* only keep a single handle on the new configuration */

  tr_log_threshold(cfg_mgr->active->internal->log_threshold);
  tr_console_threshold(cfg_mgr->active->internal->console_threshold);

  return TR_CFG_SUCCESS;
}


TR_CFG_RC tr_cfg_validate(TR_CFG *trc)
{
  TR_CFG_RC rc = TR_CFG_SUCCESS;

  if (!trc)
    return TR_CFG_BAD_PARAMS;

  if ((NULL == trc->internal)||
      (NULL == trc->internal->hostname)) {
    tr_debug("tr_cfg_validate: Error: No internal configuration, or no hostname.");
    rc = TR_CFG_ERROR;
  }

  if (NULL == trc->rp_clients) {
    tr_debug("tr_cfg_validate: Error: No RP Clients configured");
    rc = TR_CFG_ERROR;
  }

  if (0==tr_comm_table_size(trc->ctable)) {
    tr_debug("tr_cfg_validate: Error: No Communities configured");
    rc = TR_CFG_ERROR;
  }

  if ((NULL == trc->default_servers) && (NULL == trc->ctable->idp_realms)) {
    tr_debug("tr_cfg_validate: Error: No default servers or IDPs configured.");
    rc = TR_CFG_ERROR;
  }
  
  return rc;
}

static void tr_cfg_log_json_error(const char *label, json_error_t *rc)
{
  tr_debug("%s: JSON parse error on line %d: %s",
	   label,
	   rc->line,
	   rc->text);
}

/**
 * Parse a config file and return its JSON structure. Also emits a serial number to the log
 * if one is present.
 *
 * @param file_with_path The file (with path!) to parse
 * @return Pointer to the result of parsing, or null on error
 */
static json_t *tr_cfg_parse_one_config_file(const char *file_with_path)
{
  json_t *jcfg=NULL;
  json_error_t rc;

  if (NULL==(jcfg=json_load_file(file_with_path, 
                                 JSON_DISABLE_EOF_CHECK|JSON_REJECT_DUPLICATES, &rc))) {
    tr_debug("tr_cfg_parse_one_config_file: Error parsing config file %s.", 
             file_with_path);
    tr_cfg_log_json_error("tr_cfg_parse_one_config_file", &rc);
    return NULL;
  }

  return jcfg;
}

/* extract serial number */
static json_int_t get_cfg_serial(json_t *jcfg)
{
  json_t *jser=NULL;

  if (NULL != (jser = json_object_get(jcfg, "serial_number"))) {
    if (json_is_integer(jser)) {
      return json_integer_value(jser);
    }
  }
  return TR_CFG_INVALID_SERIAL;
}

/**
 * Helper to free an array returned by tr_cfg_parse_config_files
 * @param n_jcfgs
 * @param jcfgs
 */
static void tr_cfg_parse_free_jcfgs(unsigned int n_jcfgs, json_t **jcfgs)
{
  int ii=0;
  for (ii=0; ii<n_jcfgs; ii++)
    json_decref(jcfgs[ii]);
  talloc_free(jcfgs);
}

/**
 * Parse a list of configuration files. Returns an array of JSON objects, free this with
 * tr_cfg_parse_free_jcfgs(), a helper function
 *
 * @param config_dir
 * @param n_files
 * @param cfg_files
 * @return
 */
static json_t **tr_cfg_parse_config_files(TALLOC_CTX *mem_ctx, unsigned int n_files, GArray *files)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  unsigned int ii=0;
  json_t **jcfgs=NULL;
  TR_CFG_FILE *this_file = NULL;

  /* first allocate the jcfgs */
  jcfgs=talloc_array(NULL, json_t *, n_files);
  if (jcfgs==NULL) {
    tr_crit("tr_parse_config_files: cannot allocate JSON structure array");
    goto cleanup;
  }
  for (ii=0; ii<n_files; ii++) {
    this_file = &g_array_index(files, TR_CFG_FILE, ii);
    jcfgs[ii]=tr_cfg_parse_one_config_file(this_file->name);
    if (jcfgs[ii]==NULL) {
      tr_err("tr_parse_config: Error parsing JSON in %s", this_file->name);
      tr_cfg_parse_free_jcfgs(ii, jcfgs); /* frees the JSON objects and the jcfgs array */
      jcfgs=NULL;
      goto cleanup;
    }

    this_file->serial = get_cfg_serial(jcfgs[ii]);
    if (this_file->serial != TR_CFG_INVALID_SERIAL) {
      tr_notice("tr_parse_config_files: Attempting to load revision %"
                    JSON_INTEGER_FORMAT
                    " of '%s'.",
                this_file->serial,
                this_file->name);
    } else {
      tr_notice("tr_parse_config_files: Attempting to load '%s'.",
                this_file->name);
    }
  }

cleanup:
  if (jcfgs)
    talloc_steal(mem_ctx, jcfgs); /* give this to the caller's context if we succeeded */
  talloc_free(tmp_ctx);
  return jcfgs;
}

/* define a type for config parse functions */
typedef TR_CFG_RC (TR_CFG_PARSE_FN)(TR_CFG *, json_t *);
/**
 * Helper function to parse a collection of JSON structures using a generic parse function.
 *
 * @param cfg Config structure to receive results
 * @param parse_fn Function to apply
 * @param n_jcfg Number of JSON structures in the array
 * @param jcfgs Pointer to an array of decoded JSON structures
 * @param key Key to extract from each jcfg before parsing, or NULL to use the object itself
 * @return TR_CFG_SUCCESS on success, _FAIL or an error code on failure
 */
static TR_CFG_RC tr_cfg_parse_helper(TR_CFG *cfg,
                                     TR_CFG_PARSE_FN parse_fn,
                                     unsigned int n_jcfg,
                                     json_t **jcfgs,
                                     const char *key)
{
  size_t ii=0;
  json_t *this_jcfg=NULL;
  TR_CFG_RC ret=TR_CFG_ERROR;

  if ((cfg==NULL) || (jcfgs==NULL) || (parse_fn==NULL))
    return TR_CFG_ERROR;

  for (ii=0; ii<n_jcfg; ii++) {
    if (key)
      this_jcfg = json_object_get(jcfgs[ii], key);
    else
      this_jcfg = jcfgs[ii];

    /* do not try to parse a missing jcfg */
    if (this_jcfg == NULL)
      continue;

    ret=parse_fn(cfg, this_jcfg);
    if (ret!=TR_CFG_SUCCESS)
      break;
  }
  return ret;
}

static void add_files(TR_CFG *cfg, unsigned int n, char **filenames)
{
  TR_CFG_FILE frec = {0};

  while ((n--) > 0) {
    frec.name = talloc_strdup(cfg, filenames[n]);
    frec.serial = TR_CFG_INVALID_SERIAL;

    g_array_append_val(cfg->files, frec);
  }
}

/**
 *  Read a list of configuration files
 *
 * @param cfg_mgr Configuration manager
 * @param n_files Number of entries in cfg_files
 * @param files_with_paths Array of filenames with path to load
 * @return TR_CFG_SUCCESS on success, TR_CFG_ERROR or a more specific error on failure
 */
TR_CFG_RC tr_parse_config(TR_CFG_MGR *cfg_mgr, unsigned int n_files, char **files_with_paths)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  json_t **jcfgs=NULL;
  TR_CFG_RC cfg_rc=TR_CFG_ERROR;

  if ((!cfg_mgr) || (!files_with_paths)) {
    cfg_rc=TR_CFG_BAD_PARAMS;
    goto cleanup;
  }

  /* get a fresh config to fill in, freeing old one if needed */
  if (cfg_mgr->new != NULL)
    tr_cfg_free(cfg_mgr->new);
  cfg_mgr->new=tr_cfg_new(tmp_ctx); /* belongs to the temporary context for now */
  if (cfg_mgr->new == NULL) {
    cfg_rc=TR_CFG_NOMEM;
    goto cleanup;
  }

  /* add the list of files to the config */
  add_files(cfg_mgr->new, n_files, files_with_paths);

  /* first parse the json */
  jcfgs=tr_cfg_parse_config_files(tmp_ctx, n_files, cfg_mgr->new->files);
  if (jcfgs==NULL) {
    cfg_rc=TR_CFG_NOPARSE;
    goto cleanup;
  }

  cfg_mgr->new->peers=trp_ptable_new(cfg_mgr); /* not sure why this isn't in cfg_mgr->new's context */

  /* now run through the parsers on the JSON */
  if ((TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_internal, n_files, jcfgs, "tr_internal"))) ||
      (TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_local_orgs, n_files, jcfgs, NULL))) ||
      (TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_peer_orgs, n_files, jcfgs, NULL))) ||
      (TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_default_servers, n_files, jcfgs,
                                                      NULL))) ||
      (TR_CFG_SUCCESS != (cfg_rc= tr_cfg_parse_helper(cfg_mgr->new, tr_cfg_parse_comms, n_files, jcfgs, NULL))))
    goto cleanup; /* cfg_rc was set above */

  /* make sure we got a complete, consistent configuration */
  if (TR_CFG_SUCCESS != tr_cfg_validate(cfg_mgr->new)) {
    tr_err("tr_parse_config: Error: INVALID CONFIGURATION");
    cfg_rc=TR_CFG_ERROR;
    goto cleanup;
  }

  /* success! */
  talloc_steal(cfg_mgr, cfg_mgr->new); /* hand this over to the cfg_mgr context */
  cfg_rc=TR_CFG_SUCCESS;

cleanup:
  if (jcfgs!=NULL)
    tr_cfg_parse_free_jcfgs(n_files, jcfgs);
  talloc_free(tmp_ctx);
  return cfg_rc;
}

static int is_cfg_file(const struct dirent *dent) {
  size_t n;

  /* Only accept filenames ending in ".cfg" and starting with a character
   * other than an ASCII '.' */

  /* filename must be at least 4 characters long to be acceptable */
  n=strlen(dent->d_name);
  if (n < 4) {
    return 0;
  }

  /* filename must not start with '.' */
  if ('.' == dent->d_name[0]) {
    return 0;
  }

  /* If the above passed and the last four characters of the filename are .cfg, accept.
   * (n.b., assumes an earlier test checked that the name is >= 4 chars long.) */
  if (0 == strcmp(&(dent->d_name[n-4]), ".cfg")) {
    return 1;
  }

  /* otherwise, return false. */
  return 0;
}

/* Find configuration files in a particular directory. Returns the
 * number of entries found, 0 if none are found, or <0 for some
 * errors. If n>=0, the cfg_files parameter will contain a newly
 * allocated array of pointers to struct dirent entries, as returned
 * by scandir(). These can be freed with tr_free_config_file_list().
 */
int tr_find_config_files(const char *config_dir, struct dirent ***cfg_files) {
  int n = 0;
  
  n = scandir(config_dir, cfg_files, is_cfg_file, alphasort);

  if (n < 0) {
    perror("scandir");
    tr_debug("tr_find_config: scandir error trying to scan %s.", config_dir);
  } 

  return n;
}

/* Free memory allocated for configuration file list returned from tr_find_config_files().
 * This can be called regardless of the return value of tr_find_config_values(). */
void tr_free_config_file_list(int n, struct dirent ***cfg_files) {
  int ii;

  /* if n < 0, then scandir did not allocate anything because it failed */
  if((n>=0) && (*cfg_files != NULL)) {
    for(ii=0; ii<n; ii++) {
      free((*cfg_files)[ii]);
    }
    free(*cfg_files); /* safe even if n==0 */
    *cfg_files=NULL; /* this will help prevent accidentally freeing twice */
  }
}
