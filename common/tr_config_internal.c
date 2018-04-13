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
 * Parse internal configuration JSON
 *
 * @param trc configuration structure to fill in
 * @param jint internal configuration JSON object
 * @return TR_CFG_SUCCESS or an error code
 */
TR_CFG_RC tr_cfg_parse_internal(TR_CFG *trc, json_t *jint)
{
  json_t *jmtd = NULL;
  json_t *jtidsp = NULL;
  json_t *jtrpsp = NULL;
  json_t *jhname = NULL;
  json_t *jlog = NULL;
  json_t *jconthres = NULL;
  json_t *jlogthres = NULL;
  json_t *jcfgpoll = NULL;
  json_t *jcfgsettle = NULL;
  json_t *jroutesweep = NULL;
  json_t *jrouteupdate = NULL;
  json_t *jtidreq_timeout = NULL;
  json_t *jtidresp_numer = NULL;
  json_t *jtidresp_denom = NULL;
  json_t *jrouteconnect = NULL;

  if ((!trc) || (!jint))
    return TR_CFG_BAD_PARAMS;

  if (NULL == trc->internal) {
    if (NULL == (trc->internal = talloc_zero(trc, TR_CFG_INTERNAL)))
      return TR_CFG_NOMEM;
  }

  if (NULL != (jmtd = json_object_get(jint, "max_tree_depth"))) {
    if (json_is_number(jmtd)) {
      trc->internal->max_tree_depth = json_integer_value(jmtd);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, max_tree_depth is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* If not configured, use the default */
    trc->internal->max_tree_depth = TR_DEFAULT_MAX_TREE_DEPTH;
  }
  if (NULL != (jtidsp = json_object_get(jint, "tids_port"))) {
    if (json_is_number(jtidsp)) {
      trc->internal->tids_port = json_integer_value(jtidsp);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, tids_port is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* If not configured, use the default */
    trc->internal->tids_port = TR_DEFAULT_TIDS_PORT;
  }
  if (NULL != (jtrpsp = json_object_get(jint, "trps_port"))) {
    if (json_is_number(jtrpsp)) {
      trc->internal->trps_port = json_integer_value(jtrpsp);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, trps_port is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* If not configured, use the default */
    trc->internal->trps_port = TR_DEFAULT_TRPS_PORT;
  }
  if (NULL != (jhname = json_object_get(jint, "hostname"))) {
    if (json_is_string(jhname)) {
      trc->internal->hostname = talloc_strdup(trc->internal, json_string_value(jhname));
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, hostname is not a string.");
      return TR_CFG_NOPARSE;
    }
  }
  if (NULL != (jcfgpoll = json_object_get(jint, "cfg_poll_interval"))) {
    if (json_is_number(jcfgpoll)) {
      trc->internal->cfg_poll_interval = json_integer_value(jcfgpoll);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, cfg_poll_interval is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    trc->internal->cfg_poll_interval = TR_CFGWATCH_DEFAULT_POLL;
  }

  if (NULL != (jcfgsettle = json_object_get(jint, "cfg_settling_time"))) {
    if (json_is_number(jcfgsettle)) {
      trc->internal->cfg_settling_time = json_integer_value(jcfgsettle);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, cfg_settling_time is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    trc->internal->cfg_settling_time = TR_CFGWATCH_DEFAULT_SETTLE;
  }

  if (NULL != (jrouteconnect = json_object_get(jint, "trp_connect_interval"))) {
    if (json_is_number(jrouteconnect)) {
      trc->internal->trp_connect_interval = json_integer_value(jrouteconnect);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, trp_connect_interval is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* if not configured, use the default */
    trc->internal->trp_connect_interval=TR_DEFAULT_TRP_CONNECT_INTERVAL;
  }

  if (NULL != (jroutesweep = json_object_get(jint, "trp_sweep_interval"))) {
    if (json_is_number(jroutesweep)) {
      trc->internal->trp_sweep_interval = json_integer_value(jroutesweep);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, trp_sweep_interval is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* if not configured, use the default */
    trc->internal->trp_sweep_interval=TR_DEFAULT_TRP_SWEEP_INTERVAL;
  }

  if (NULL != (jrouteupdate = json_object_get(jint, "trp_update_interval"))) {
    if (json_is_number(jrouteupdate)) {
      trc->internal->trp_update_interval = json_integer_value(jrouteupdate);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, trp_update_interval is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* if not configured, use the default */
    trc->internal->trp_update_interval=TR_DEFAULT_TRP_UPDATE_INTERVAL;
  }

  if (NULL != (jtidreq_timeout = json_object_get(jint, "tid_request_timeout"))) {
    if (json_is_number(jtidreq_timeout)) {
      trc->internal->tid_req_timeout = json_integer_value(jtidreq_timeout);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, tid_request_timeout is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* if not configured, use the default */
    trc->internal->tid_req_timeout=TR_DEFAULT_TID_REQ_TIMEOUT;
  }

  if (NULL != (jtidresp_numer = json_object_get(jint, "tid_response_numerator"))) {
    if (json_is_number(jtidresp_numer)) {
      trc->internal->tid_resp_numer = json_integer_value(jtidresp_numer);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, tid_response_numerator is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* if not configured, use the default */
    trc->internal->tid_resp_numer=TR_DEFAULT_TID_RESP_NUMER;
  }

  if (NULL != (jtidresp_denom = json_object_get(jint, "tid_response_denominator"))) {
    if (json_is_number(jtidresp_denom)) {
      trc->internal->tid_resp_denom = json_integer_value(jtidresp_denom);
    } else {
      tr_debug("tr_cfg_parse_internal: Parsing error, tid_response_denominator is not a number.");
      return TR_CFG_NOPARSE;
    }
  } else {
    /* if not configured, use the default */
    trc->internal->tid_resp_denom=TR_DEFAULT_TID_RESP_DENOM;
  }

  if (NULL != (jlog = json_object_get(jint, "logging"))) {
    if (NULL != (jlogthres = json_object_get(jlog, "log_threshold"))) {
      if (json_is_string(jlogthres)) {
        trc->internal->log_threshold = str2sev(json_string_value(jlogthres));
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, log_threshold is not a string.");
        return TR_CFG_NOPARSE;
      }
    } else {
      /* If not configured, use the default */
      trc->internal->log_threshold = TR_DEFAULT_LOG_THRESHOLD;
    }

    if (NULL != (jconthres = json_object_get(jlog, "console_threshold"))) {
      if (json_is_string(jconthres)) {
        trc->internal->console_threshold = str2sev(json_string_value(jconthres));
      } else {
        tr_debug("tr_cfg_parse_internal: Parsing error, console_threshold is not a string.");
        return TR_CFG_NOPARSE;
      }
    } else {
      /* If not configured, use the default */
      trc->internal->console_threshold = TR_DEFAULT_CONSOLE_THRESHOLD;
    }
  } else {
    /* If not configured, use the default */
    trc->internal->console_threshold = TR_DEFAULT_CONSOLE_THRESHOLD;
    trc->internal->log_threshold = TR_DEFAULT_LOG_THRESHOLD;
  }

  tr_debug("tr_cfg_parse_internal: Internal config parsed.");
  return TR_CFG_SUCCESS;
}
