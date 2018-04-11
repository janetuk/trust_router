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


#include <talloc.h>
#include <gmodule.h>
#include <string.h>

#include <tr_mon.h>

// Monitoring common code

/**
 * This method defines the command strings
 */
const char *cmd_to_string(TR_MON_CMD cmd)
{
  switch(cmd) {
    case MON_CMD_UNKNOWN:
      return NULL;

    case MON_CMD_RECONFIGURE:
      return "reconfigure";

    case MON_CMD_SHOW:
      return "show";
  }
  return NULL;
}

// Helper macro for the cmd_from_string method
#define return_if_matches(s, cmd)            \
  do {                                       \
    if (strcmp((s), cmd_to_string(cmd))==0)  \
      return (cmd);                          \
  } while(0)

TR_MON_CMD cmd_from_string(const char *s)
{
  return_if_matches(s, MON_CMD_RECONFIGURE);
  return_if_matches(s, MON_CMD_SHOW);
  return MON_CMD_UNKNOWN;
}
#undef return_if_matches

/**
 * This method defines the option type strings
 */
const char *opt_type_to_string(TR_MON_OPT_TYPE opt_type)
{
  switch(opt_type) {
    case OPT_TYPE_UNKNOWN:
      return NULL;

    case OPT_TYPE_SHOW_VERSION:
      return "version";

    case OPT_TYPE_SHOW_SERIAL:
      return "serial";

    case OPT_TYPE_SHOW_UPTIME:
      return "uptime";

    case OPT_TYPE_SHOW_TID_REQ_COUNT:
      return "tid_req_count";

    case OPT_TYPE_SHOW_TID_REQ_PENDING:
      return "tid_req_pending";

    case OPT_TYPE_SHOW_ROUTES:
      return "routes";

    case OPT_TYPE_SHOW_COMMUNITIES:
      return "communities";
  }
  return NULL;
}

// Helper macro for the opt_type_from_string method
#define return_if_matches(s, cmd)                 \
  do {                                            \
    if (strcmp((s), opt_type_to_string(cmd))==0)  \
      return (cmd);                               \
  } while(0)

TR_MON_OPT_TYPE opt_type_from_string(const char *s)
{
  return_if_matches(s, OPT_TYPE_SHOW_VERSION);
  return_if_matches(s, OPT_TYPE_SHOW_SERIAL);
  return_if_matches(s, OPT_TYPE_SHOW_UPTIME);
  return_if_matches(s, OPT_TYPE_SHOW_TID_REQ_COUNT);
  return_if_matches(s, OPT_TYPE_SHOW_TID_REQ_PENDING);
  return_if_matches(s, OPT_TYPE_SHOW_ROUTES);
  return_if_matches(s, OPT_TYPE_SHOW_COMMUNITIES);
  return OPT_TYPE_UNKNOWN;
}
#undef return_if_matches
