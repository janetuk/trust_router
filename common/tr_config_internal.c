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

#include <talloc.h>
#include <jansson.h>
#include <tr_debug.h>
#include <tr_config.h>
#include <tr_cfgwatch.h>

/**
 * Parse a boolean
 *
 * If the key does not exist in the src object, returns success but does fill in *dest.
 *
 * @param src JSON object to pull a value from
 * @param key key to pull
 * @param dest (output) pointer to an allocated integer
 * @return TR_CFG_SUCCESS or an error code
 */
static TR_CFG_RC tr_cfg_parse_boolean(json_t *src, const char *key, int *dest)
{
  json_t *jtmp;

  /* Validate parameters */
  if ((src == NULL) || (key == NULL) || (dest == NULL))
    return TR_CFG_BAD_PARAMS;

  /* See if we have a value for this key; do nothing if not */
  jtmp = json_object_get(src, key);
  if (jtmp) {
    if (json_is_boolean(jtmp)) {
      *dest = json_is_true(jtmp);
    } else {
      tr_debug("tr_cfg_parse_unsigned: Parsing error, %s is not a boolean.", key);
      return TR_CFG_NOPARSE;
    }
  }

  return TR_CFG_SUCCESS;
}

/**
 * Parse a signed integer
 *
 * If the key does not exist in the src object, returns success but does fill in *dest.
 *
 * @param src JSON object to pull a value from
 * @param key key to pull
 * @param dest (output) pointer to an allocated integer
 * @return TR_CFG_SUCCESS or an error code
 */
static TR_CFG_RC tr_cfg_parse_integer(json_t *src, const char *key, int *dest)
{
  json_t *jtmp;

  /* Validate parameters */
  if ((src == NULL) || (key == NULL) || (dest == NULL))
    return TR_CFG_BAD_PARAMS;

  /* See if we have a value for this key; do nothing if not */
  jtmp = json_object_get(src, key);
  if (jtmp) {
    if (json_is_number(jtmp)) {
      *dest = (int) json_integer_value(jtmp);
    } else {
      tr_debug("tr_cfg_parse_unsigned: Parsing error, %s is not a number.", key);
      return TR_CFG_NOPARSE;
    }
  }

  return TR_CFG_SUCCESS;
}

/**
 * Parse an unsigned integer
 *
 * If the key does not exist in the src object, returns success but does fill in *dest.
 *
 * @param src JSON object to pull a value from
 * @param key key to pull
 * @param dest (output) pointer to an allocated unsigned integer
 * @return TR_CFG_SUCCESS or an error code
 */
static TR_CFG_RC tr_cfg_parse_unsigned(json_t *src, const char *key, unsigned int *dest)
{
  json_t *jtmp;

  /* Validate parameters */
  if ((src == NULL) || (key == NULL) || (dest == NULL))
    return TR_CFG_BAD_PARAMS;

  /* See if we have a value for this key; do nothing if not */
  jtmp = json_object_get(src, key);
  if (jtmp) {
    if (! json_is_number(jtmp)) {
      tr_debug("tr_cfg_parse_unsigned: Parsing error, %s is not a number.", key);
      return TR_CFG_NOPARSE;
    } else if (json_integer_value(jtmp) < 0) {
      tr_debug("tr_cfg_parse_unsigned: Value %d < 0.", json_integer_value(jtmp));
      return TR_CFG_NOPARSE;
    } else {
      *dest = (unsigned int) json_integer_value(jtmp);
    }
  }

  return TR_CFG_SUCCESS;
}

/**
 * Parse a string
 *
 * If the key does not exist in the src object, returns success but does not allocate
 * a return value in dest. Nulls the destination pointer if there is no return value.
 *
 * Return value is allocated in talloc's NULL context and must be freed with talloc_free()
 * or put into a non-NULL context with talloc_steal()
 *
 * @param src JSON object to pull a value from
 * @param key key to pull
 * @param dest (output) pointer to a pointer that will hold the newly allocated return value
 * @return TR_CFG_SUCCESS or an error code
 */
static TR_CFG_RC tr_cfg_parse_string(json_t *src, const char *key, const char **dest)
{
  json_t *jtmp;

  /* Validate parameters */
  if ((src == NULL) || (key == NULL) || (dest == NULL))
    return TR_CFG_BAD_PARAMS;

  /* See if we have a value for this key; do nothing if not */
  jtmp = json_object_get(src, key);
  if (!jtmp) {
    *dest = NULL; /* No return value, null this out */
  } else {
    if (json_is_string(jtmp)) {
      *dest = talloc_strdup(NULL, json_string_value(jtmp));
    } else {
      tr_debug("tr_cfg_parse_string: Parsing error, %s is not a string.", key);
      return TR_CFG_NOPARSE;
    }
  }

  return TR_CFG_SUCCESS;
}

/**
 * Set default values for settings that have them
 *
 * @param cfg configuration structure to fill in, not null
 */
static void set_defaults(TR_CFG_INTERNAL *cfg)
{
  cfg->max_tree_depth = TR_DEFAULT_MAX_TREE_DEPTH;
  cfg->tids_port = TR_DEFAULT_TIDS_PORT;
  cfg->trps_port = TR_DEFAULT_TRPS_PORT;
  cfg->mons_port = TR_DEFAULT_MONITORING_PORT;
  cfg->cfg_poll_interval = TR_CFGWATCH_DEFAULT_POLL;
  cfg->cfg_settling_time = TR_CFGWATCH_DEFAULT_SETTLE;
  cfg->trp_connect_interval = TR_DEFAULT_TRP_CONNECT_INTERVAL;
  cfg->trp_sweep_interval = TR_DEFAULT_TRP_SWEEP_INTERVAL;
  cfg->trp_update_interval = TR_DEFAULT_TRP_UPDATE_INTERVAL;
  cfg->tid_req_timeout = TR_DEFAULT_TID_REQ_TIMEOUT;
  cfg->tid_resp_numer = TR_DEFAULT_TID_RESP_NUMER;
  cfg->tid_resp_denom = TR_DEFAULT_TID_RESP_DENOM;
  cfg->log_threshold = TR_DEFAULT_LOG_THRESHOLD;
  cfg->console_threshold = TR_DEFAULT_CONSOLE_THRESHOLD;
  cfg->monitoring_credentials = NULL;
}

/* Helper that checks return value of a parse fn and returns if it failed */
#define NOPARSE_UNLESS(x)    \
do {                         \
  if ((x) != TR_CFG_SUCCESS) \
    return TR_CFG_NOPARSE;   \
} while(0)

static TR_CFG_RC tr_cfg_parse_monitoring(TR_CFG *trc, json_t *jmon)
{
  int enabled = 1; /* assume we are enabled unless we are told not to be */

  NOPARSE_UNLESS(tr_cfg_parse_boolean(jmon, "enabled", &enabled));
  if (enabled) {
    NOPARSE_UNLESS(tr_cfg_parse_integer(jmon, "port", &(trc->internal->mons_port)));
    if (trc->internal->mons_port == 0) {
      /* Catch this as a special case because 0 means that monitoring is disabled. */
      tr_debug("tr_cfg_parse_monitoring: invalid monitoring port (0). Use \"enabled\":false to disable monitoring.");
      return TR_CFG_BAD_PARAMS;
    }
    NOPARSE_UNLESS(tr_cfg_parse_gss_names(trc->internal,
                                          json_object_get(jmon, "authorized_credentials"),
                                          &(trc->internal->monitoring_credentials)));
  }

  return TR_CFG_SUCCESS;
}

/**
 * Parse internal configuration JSON
 *
 * @param trc configuration structure to fill in
 * @param jint internal configuration JSON object
 * @return TR_CFG_SUCCESS or an error code
 */
TR_CFG_RC tr_cfg_parse_internal(TR_CFG *trc, json_t *jint)
{
  json_t *jtmp = NULL;
  const char *s = NULL;

  if ((!trc) || (!jint))
    return TR_CFG_BAD_PARAMS;

  /* If we don't yet have an internal config, allocate one and set defaults. If it
   * already exists, do not disturb existing settings. */
  if (NULL == trc->internal) {
    if (NULL == (trc->internal = talloc_zero(trc, TR_CFG_INTERNAL)))
      return TR_CFG_NOMEM;
    set_defaults(trc->internal); /* Install defaults for any unspecified settings */
  }

  NOPARSE_UNLESS(tr_cfg_parse_string(jint, "hostname", &(trc->internal->hostname)));
  talloc_steal(trc->internal, trc->internal->hostname);

  NOPARSE_UNLESS(tr_cfg_parse_unsigned(jint, "max_tree_depth",           &(trc->internal->max_tree_depth)));
  NOPARSE_UNLESS(tr_cfg_parse_integer(jint, "tids_port",                &(trc->internal->tids_port)));
  NOPARSE_UNLESS(tr_cfg_parse_integer(jint, "trps_port",                &(trc->internal->trps_port)));
  NOPARSE_UNLESS(tr_cfg_parse_unsigned(jint, "cfg_poll_interval",        &(trc->internal->cfg_poll_interval)));
  NOPARSE_UNLESS(tr_cfg_parse_unsigned(jint, "cfg_settling_time",        &(trc->internal->cfg_settling_time)));
  NOPARSE_UNLESS(tr_cfg_parse_unsigned(jint, "trp_connect_interval",     &(trc->internal->trp_connect_interval)));
  NOPARSE_UNLESS(tr_cfg_parse_unsigned(jint, "trp_sweep_interval",       &(trc->internal->trp_sweep_interval)));
  NOPARSE_UNLESS(tr_cfg_parse_unsigned(jint, "trp_update_interval",      &(trc->internal->trp_update_interval)));
  NOPARSE_UNLESS(tr_cfg_parse_unsigned(jint, "tid_request_timeout",      &(trc->internal->tid_req_timeout)));
  NOPARSE_UNLESS(tr_cfg_parse_unsigned(jint, "tid_response_numerator",   &(trc->internal->tid_resp_numer)));
  NOPARSE_UNLESS(tr_cfg_parse_unsigned(jint, "tid_response_denominator", &(trc->internal->tid_resp_denom)));

  /* Parse the logging section */
  if (NULL != (jtmp = json_object_get(jint, "logging"))) {
    NOPARSE_UNLESS(tr_cfg_parse_string(jtmp, "log_threshold", &s));
    if (s) {
      trc->internal->log_threshold = str2sev(s);
      talloc_free((void *) s);
    }

    NOPARSE_UNLESS(tr_cfg_parse_string(jtmp, "console_threshold", &s));
    if (s) {
      trc->internal->console_threshold = str2sev(s);
      talloc_free((void *) s);
    }
  }

  /* Parse the monitoring section */
  if (NULL != (jtmp = json_object_get(jint, "monitoring"))) {
    NOPARSE_UNLESS(tr_cfg_parse_monitoring(trc, jtmp));
  }

  tr_debug("tr_cfg_parse_internal: Internal config parsed.");
  return TR_CFG_SUCCESS;
}

static int invalid_port(int port)
{
  return ((port <= 0) || (port > 65536));
}

/**
 * Validate the internal configuration of the trust router
 *
 * Validates fields, emitting errors if there are any. Safe to call with
 * a null int_cfg, but this results in an error being returned.
 *
 * @param int_cfg pointer to an internal configuration (NULL is safe)
 * @return success or error
 */
TR_CFG_RC tr_cfg_validate_internal(TR_CFG_INTERNAL *int_cfg)
{
  TR_CFG_RC rc;

  /* ensure we have an internal configuration and exit if not  */
  if (NULL == int_cfg) {
    tr_debug("tr_cfg_validate_internal: No internal configuration present.");
    return TR_CFG_BAD_PARAMS;
  }

  /* Assume we are going to succeed. If any errors are encountered, emit a message
   * and set the return code to an error. Don't exit early, emit all the errors
   * at once if we can. */
  rc = TR_CFG_SUCCESS;

  /*** Validate hostname ***/
  if (NULL == int_cfg->hostname) {
    tr_debug("tr_cfg_validate_internal: No hostname specified.");
    rc = TR_CFG_ERROR;
  }

  /*** Validate various intervals ***/
  if (TR_MIN_TRP_CONNECT_INTERVAL > int_cfg->trp_connect_interval) {
    tr_debug(
        "tr_cfg_validate_internal: Error: trp_connect_interval must be at least %d (currently %d).",
        TR_MIN_TRP_CONNECT_INTERVAL, int_cfg->trp_connect_interval);
    rc = TR_CFG_ERROR;
  }

  if (TR_MIN_TRP_SWEEP_INTERVAL > int_cfg->trp_sweep_interval) {
    tr_debug(
        "tr_cfg_validate_internal: Error: trp_sweep_interval must be at least %d (currently %d).",
        TR_MIN_TRP_SWEEP_INTERVAL, int_cfg->trp_sweep_interval);
    rc = TR_CFG_ERROR;
  }

  if (TR_MIN_TRP_UPDATE_INTERVAL > int_cfg->trp_update_interval) {
    tr_debug(
        "tr_cfg_validate_internal: Error: trp_update_interval must be at least %d (currently %d).",
        TR_MIN_TRP_UPDATE_INTERVAL, int_cfg->trp_update_interval);
    rc = TR_CFG_ERROR;
  }

  if (TR_MIN_CFG_POLL_INTERVAL > int_cfg->cfg_poll_interval) {
    tr_debug(
        "tr_cfg_validate_internal: Error: cfg_poll_interval must be at least %d (currently %d).",
        TR_MIN_CFG_POLL_INTERVAL, int_cfg->cfg_poll_interval);
    rc = TR_CFG_ERROR;
  }

  if (TR_MIN_CFG_SETTLING_TIME > int_cfg->cfg_settling_time) {
    tr_debug(
        "tr_cfg_validate_internal: Error: cfg_settling_time must be at least %d (currently %d).",
        TR_MIN_CFG_SETTLING_TIME, int_cfg->cfg_settling_time);
    rc = TR_CFG_ERROR;
  }

  /*** Validate ports ***/
  if (invalid_port(int_cfg->tids_port)) {
    tr_debug("tr_cfg_validate_internal: Error: invalid tids_port (%d).", int_cfg->tids_port);
    rc = TR_CFG_ERROR;
  }

  if (invalid_port(int_cfg->trps_port)) {
    tr_debug("tr_cfg_validate_internal: Error: invalid trps_port (%d).", int_cfg->trps_port);
    rc = TR_CFG_ERROR;
  }

  /* we allow 0 as the monitoring port - it means off */
  if ((int_cfg->mons_port != 0) && invalid_port(int_cfg->mons_port)) {
    tr_debug("tr_cfg_validate_internal: Error: invalid monitoring port (%d).", int_cfg->mons_port);
    rc = TR_CFG_ERROR;
  }

  /*** Validate tid request timeout ***/
  if (TR_MIN_TID_REQ_TIMEOUT > int_cfg->tid_req_timeout) {
    tr_debug("tr_cfg_validate_internal: Error: tid_request_timeout must be at least %d (currently %d).",
             TR_MIN_TID_REQ_TIMEOUT, int_cfg->tid_req_timeout);
    rc = TR_CFG_ERROR;
  }

  /*** Validate tid response parameters ***/
  if ((int_cfg->tid_resp_numer <= 0)
      || (int_cfg->tid_resp_denom <= 0)
      || (int_cfg->tid_resp_numer > int_cfg->tid_resp_denom)) {
    tr_debug("tr_cfg_validate_internal: Error: invalid tid_response_numerator / tid_response_denominator. Both must be positive and the numerator/denominator ratio must be <= 1 (currently %d/%d).",
             int_cfg->tid_resp_numer, int_cfg->tid_resp_denom);
    rc = TR_CFG_ERROR;
  }
  return rc;
}