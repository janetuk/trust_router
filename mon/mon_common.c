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
#include <glib.h>
#include <string.h>

#include <mon_internal.h>

// Monitoring common code

struct mon_cmd_entry {
  MON_CMD code;
  const char *name;
};

struct mon_opt_entry {
  MON_OPT_TYPE code;
  MON_CMD cmd_code;
  const char *name;
};

/* Table of commands */
struct mon_cmd_entry mon_cmd_table[] = {
    { MON_CMD_SHOW, "show" },
    { MON_CMD_UNKNOWN } /* list terminator */
};

/* Table of options */
struct  mon_opt_entry mon_opt_table[] = {
    { OPT_TYPE_SHOW_VERSION,            MON_CMD_SHOW,  "version"            },
    { OPT_TYPE_SHOW_CONFIG_FILES,       MON_CMD_SHOW,  "config_files"       },
    { OPT_TYPE_SHOW_UPTIME,             MON_CMD_SHOW,  "uptime"             },
    { OPT_TYPE_SHOW_TID_REQS_PROCESSED, MON_CMD_SHOW,  "tid_reqs_processed" },
    { OPT_TYPE_SHOW_TID_REQS_FAILED,    MON_CMD_SHOW,  "tid_reqs_failed"    },
    { OPT_TYPE_SHOW_TID_REQS_PENDING,   MON_CMD_SHOW,  "tid_reqs_pending"   },
    { OPT_TYPE_SHOW_TID_ERROR_COUNT,    MON_CMD_SHOW,  "tid_error_count"    },
    { OPT_TYPE_SHOW_ROUTES,             MON_CMD_SHOW,  "routes"             },
    { OPT_TYPE_SHOW_PEERS,              MON_CMD_SHOW,  "peers"              },
    { OPT_TYPE_SHOW_COMMUNITIES,        MON_CMD_SHOW,  "communities"        },
    { OPT_TYPE_SHOW_REALMS,             MON_CMD_SHOW,  "realms"             },
    { OPT_TYPE_SHOW_RP_CLIENTS,         MON_CMD_SHOW,  "rp_clients"         },
    { OPT_TYPE_UNKNOWN } /* list terminator */
};

/*** Commands ***/

static struct mon_cmd_entry *find_cmd_entry(MON_CMD code)
{
  struct mon_cmd_entry *entry;

  for (entry=mon_cmd_table; entry->code != MON_CMD_UNKNOWN; entry++) {
    if (entry->code == code)
      return entry;
  }

  return NULL;
}

const char *mon_cmd_to_string(MON_CMD cmd)
{
  struct mon_cmd_entry *entry = find_cmd_entry(cmd);

  if (entry)
    return entry->name;

  return NULL;
}

MON_CMD mon_cmd_from_string(const char *s)
{
  struct mon_cmd_entry *entry;

  for (entry=mon_cmd_table; entry->code != MON_CMD_UNKNOWN; entry++) {
    if (strcmp(s, entry->name) == 0)
      return entry->code;
  }

  return MON_CMD_UNKNOWN;
}

/*** Options ***/

static struct mon_opt_entry *find_opt_entry(MON_OPT_TYPE code)
{
  struct mon_opt_entry *entry;

  for (entry=mon_opt_table; entry->code != OPT_TYPE_UNKNOWN; entry++) {
    if (entry->code == code)
      return entry;
  }

  return NULL;
}

const char *mon_opt_type_to_string(MON_OPT_TYPE opt_type)
{
  struct mon_opt_entry *entry = find_opt_entry(opt_type);

  if (entry)
    return entry->name;

  return NULL;
}

MON_OPT_TYPE mon_opt_type_from_string(const char *s)
{
  struct mon_opt_entry *entry;

  for (entry=mon_opt_table; entry->code != OPT_TYPE_UNKNOWN; entry++) {
    if (strcmp(s, entry->name) == 0)
      return entry->code;
  }

  return OPT_TYPE_UNKNOWN;
}
