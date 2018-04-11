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

#include <tr_mon.h>

// Monitoring request message common code

/**
 * Destructor used by talloc to ensure proper cleanup
 */
static int tr_mon_req_destructor(void *object)
{
  TR_MON_REQ *req = talloc_get_type_abort(object, TR_MON_REQ);
  if (req->options) {
    g_array_unref(req->options);
  }
  return 0;
}

/**
 * Allocate a new monitoring request
 *
 * @param mem_ctx talloc context for the new request
 * @param cmd command for the request
 * @return newly allocated request, or null on error
 */
TR_MON_REQ *tr_mon_req_new(TALLOC_CTX *mem_ctx, TR_MON_CMD cmd)
{
  TR_MON_REQ *req=talloc(mem_ctx, TR_MON_REQ);
  if (req) {
    req->command = cmd;
    req->options = g_array_new(FALSE, FALSE, sizeof(TR_MON_OPT));
    talloc_set_destructor((void *)req, tr_mon_req_destructor);
  }
  return req;
}

/**
 * Free a monitoring request
 *
 * @param req request to free, must not be null
 */
void tr_mon_req_free(TR_MON_REQ *req)
{
  talloc_free(req);
}

/**
 * Add an option to a TR_MON_REQ
 * @param req request to operate on, not null
 * @param opt_type type of option
 * @return TR_MON_SUCCESS on success, error code on error
 */
TR_MON_RC tr_mon_req_add_option(TR_MON_REQ *req, TR_MON_OPT_TYPE opt_type)
{
  TR_MON_OPT new_opt; // not a pointer

  /* Validate parameters */
  if ((req == NULL) || (opt_type == OPT_TYPE_UNKNOWN)) {
    return TR_MON_BADARG;
  }

  new_opt.type = opt_type;

  /* Add the new option to the list */
  g_array_append_val(req->options, new_opt);
  return TR_MON_SUCCESS;
}

size_t tr_mon_req_opt_count(TR_MON_REQ *req)
{
  return req->options->len;
}

TR_MON_OPT *tr_mon_req_opt_index(TR_MON_REQ *req, size_t index)
{
  TR_MON_OPT *result = &g_array_index(req->options, TR_MON_OPT, index);
  return result;
}
