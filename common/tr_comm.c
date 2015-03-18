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

#include <trust_router/tr_name.h>
#include <tr_config.h>
#include <tr.h>
#include <tr_comm.h>
#include <tr_rp.h>
#include <tr_debug.h>

TR_IDP_REALM *tr_find_comm_idp (TR_COMM *comm, TR_NAME *idp_realm)
{
  TR_IDP_REALM *idp;

  if ((!comm) || (!idp_realm)) {
    return NULL;
  }

  for (idp = comm->idp_realms; NULL != idp; idp = idp->next) {
    if (!tr_name_cmp (idp_realm, idp->realm_id)) {
      tr_debug("tr_find_comm_idp: Found %s.", idp_realm->buf);
      return idp;
    }
  }
  /* if we didn't find one, return NULL */ 
  return NULL;
}

TR_RP_REALM *tr_find_comm_rp (TR_COMM *comm, TR_NAME *rp_realm)
{
  TR_RP_REALM *rp;

  if ((!comm) || (!rp_realm)) {
    return NULL;
  }

  for (rp = comm->rp_realms; NULL != rp; rp = rp->next) {
    if (!tr_name_cmp (rp_realm, rp->realm_name)) {
      tr_debug("tr_find_comm_idp: Found %s.", rp_realm->buf);
      return rp;
    }
  }
  /* if we didn't find one, return NULL */ 
  return NULL;
}

TR_COMM *tr_comm_lookup(TR_INSTANCE *tr, TR_NAME *comm) 
{
  TR_COMM *cfg_comm = NULL;

  for (cfg_comm = tr->active_cfg->comms; NULL != cfg_comm; cfg_comm = cfg_comm->next) {
    if ((cfg_comm->id->len == comm->len) &&
	(!strncmp(cfg_comm->id->buf, comm->buf, comm->len)))
      return cfg_comm;
  }
  return NULL;
}
