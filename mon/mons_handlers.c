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

/* Handlers for monitoring requests */

#include <tr_debug.h>
#include <mon_internal.h>
#include "mons_handlers.h"

typedef MON_RESP *(MONS_HANDLER_FUNC)(TALLOC_CTX *, MONS_INSTANCE *, MON_REQ *);

/* Prototypes for the dispatch table */
static MON_RESP *mons_handle_reconfigure(TALLOC_CTX *mem_ctx, MONS_INSTANCE *mons, MON_REQ *req);


struct dispatch_table_entry {
  MON_CMD command;
  MONS_HANDLER_FUNC *handler;
};

static struct dispatch_table_entry dispatch_table[] = {
    {MON_CMD_SHOW, mons_handle_show},
    {MON_CMD_RECONFIGURE, mons_handle_reconfigure},
    {MON_CMD_UNKNOWN} /* Must be the last entry in the table */
};

/**
 * Call the appropriate handler for a request
 *
 * @return a MON_RESP structure or null if there was a processing error
 */
MON_RESP *mons_handle_request(TALLOC_CTX *mem_ctx, MONS_INSTANCE *mons, MON_REQ *req)
{
  struct dispatch_table_entry *entry = dispatch_table;

  tr_debug("mons_handle_request: Handling a request");

  /* Find the handler */
  while ((entry->command != req->command) && (entry->command != MON_CMD_UNKNOWN)) {
    entry++;
  }

  /* See if we found a handler */
  if (entry->command == MON_CMD_UNKNOWN) {
    tr_info("mons_handle_request: Unknown or unsupported monitoring request received");
    return NULL;
  }

  /* Call the handler */
  tr_debug("mons_handle_request: Calling handler for %s command", mon_cmd_to_string(entry->command));
  return entry->handler(mem_ctx, mons, req);
}

static MON_RESP *mons_handle_reconfigure(TALLOC_CTX *mem_ctx, MONS_INSTANCE *mons, MON_REQ *req)
{
  return NULL;
}
