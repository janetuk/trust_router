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

#include <talloc.h>

#include <tr_rp.h>
#include <trust_router/tr_name.h>
#include <tr_comm.h>
#include <tr_debug.h>

static int tr_comm_destructor(void *obj)
{
  TR_COMM *comm=talloc_get_type_abort(obj, TR_COMM);
  if (comm->id!=NULL)
    tr_free_name(comm->id);
  return 0;
}

TR_COMM *tr_comm_new(TALLOC_CTX *mem_ctx)
{
  TR_COMM *comm=talloc(mem_ctx, TR_COMM);
  if (comm!=NULL) {
    comm->next=NULL;
    comm->id=NULL;
    comm->type=TR_COMM_UNKNOWN;
    comm->apcs=NULL;
    comm->idp_realms=NULL;
    comm->rp_realms=NULL;
    talloc_set_destructor((void *)comm, tr_comm_destructor);
  }
  return comm;
}

void tr_comm_free(TR_COMM *comm)
{
  talloc_free(comm);
}

/* does not take responsibility for freeing IDP realm */
void tr_comm_add_idp_realm(TR_COMM *comm, TR_IDP_REALM *realm)
{
  TR_IDP_REALM *cur=NULL;

  if (comm->idp_realms==NULL)
    comm->idp_realms=realm;
  else {
    for (cur=comm->idp_realms; cur->comm_next!=NULL; cur=cur->comm_next) { }
    cur->comm_next=realm;
  }
}

/* does not take responsibility for freeing RP realm */
void tr_comm_add_rp_realm(TR_COMM *comm, TR_RP_REALM *realm)
{
  TR_RP_REALM *cur=NULL;

  if (comm->rp_realms==NULL)
    comm->rp_realms=realm;
  else {
    for (cur=comm->rp_realms; cur->next!=NULL; cur=cur->next) { }
    cur->next=realm;
  }
}

static TR_COMM *tr_comm_tail(TR_COMM *comm)
{
  if (comm==NULL)
    return comm;

  while (comm->next!=NULL)
    comm=comm->next;
  return comm;
}

/* All list members are in the talloc context of the head.
 * This will require careful thought if entries are ever removed
 * or shuffled between lists. 
 * Call like comms=tr_comm_add(comms, new_comm); */
TR_COMM *tr_comm_add(TR_COMM *comms, TR_COMM *new)
{
  if (comms==NULL)
    comms=new;
  else {
    tr_comm_tail(comms)->next=new;
    while(new!=NULL) {
      talloc_steal(comms, new);
      new=new->next;
    }
  }
  return comms;
}

TR_IDP_REALM *tr_find_comm_idp (TR_COMM *comm, TR_NAME *idp_realm)
{
  TR_IDP_REALM *idp;

  if ((!comm) || (!idp_realm)) {
    return NULL;
  }

  for (idp = comm->idp_realms; NULL != idp; idp = idp->comm_next) {
    if (!tr_name_cmp (idp_realm, idp->realm_id)) {
      tr_debug("tr_find_comm_idp: Found IdP %s in community %s.", idp_realm->buf, comm->id->buf);
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
      tr_debug("tr_find_comm_rp: Found RP %s in community %s.", rp_realm->buf, comm->id->buf);
      return rp;
    }
  }
  /* if we didn't find one, return NULL */ 
  return NULL;
}

TR_COMM *tr_comm_lookup(TR_COMM *comms, TR_NAME *comm_name) 
{
  TR_COMM *cfg_comm = NULL;

  for (cfg_comm = comms; NULL != cfg_comm; cfg_comm = cfg_comm->next) {
    if ((cfg_comm->id->len == comm_name->len) &&
	(!strncmp(cfg_comm->id->buf, comm_name->buf, comm_name->len)))
      return cfg_comm;
  }
  return NULL;
}
