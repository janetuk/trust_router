/*
 * Copyright (c) 2016, JANET(UK)
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

#include <jansson.h>
#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <tr_comm.h>
#include <tr_apc.h>
#include <tr_debug.h>


/* static prototypes */
static TRP_INFOREC_DATA *trp_inforec_route_new(TALLOC_CTX *mem_ctx);
static void trp_inforec_route_print(TRP_INFOREC_DATA *);
static TRP_INFOREC_DATA *trp_inforec_comm_new(TALLOC_CTX *mem_ctx);
static void trp_inforec_comm_print(TRP_INFOREC_DATA *);


struct trp_inforec_type_entry {
  const char *name;
  TRP_INFOREC_TYPE type;
  TRP_INFOREC_DATA *(*allocate)(TALLOC_CTX *);
  void (*print)(TRP_INFOREC_DATA *);
};
static struct trp_inforec_type_entry trp_inforec_type_table[] = {
  { "route", TRP_INFOREC_TYPE_ROUTE, trp_inforec_route_new, trp_inforec_route_print },
  { "comm", TRP_INFOREC_TYPE_COMMUNITY, trp_inforec_comm_new, trp_inforec_comm_print },
  { NULL, TRP_INFOREC_TYPE_UNKNOWN, NULL, NULL } /* must be the last entry */
};


/* look up an entry in the trp_inforec_type_table */
static struct trp_inforec_type_entry *get_trp_inforec_type_entry(TRP_INFOREC_TYPE msgtype)
{
  struct trp_inforec_type_entry *entry=trp_inforec_type_table;

  while ((entry->type != TRP_INFOREC_TYPE_UNKNOWN)
        && (entry->type != msgtype)) {
    entry ++;
  }
  return entry;
}

/* translate strings to codes */
TRP_INFOREC_TYPE trp_inforec_type_from_string(const char *s)
{
  struct trp_inforec_type_entry *entry=trp_inforec_type_table;

  while ((entry->type != TRP_INFOREC_TYPE_UNKNOWN)
        && (strcmp(s, entry->name)!=0)) {
    entry++;
  }
  return entry->type;
}
/* translate codes to strings (do not need to be freed) 
 * Returns NULL on an unknown code */
const char *trp_inforec_type_to_string(TRP_INFOREC_TYPE msgtype)
{
  struct trp_inforec_type_entry *entry=get_trp_inforec_type_entry(msgtype);
  return entry->name;
}

/* called by talloc when destroying an update message body */
static int trp_inforec_route_destructor(void *object)
{
  TRP_INFOREC_ROUTE *body=talloc_get_type_abort(object, TRP_INFOREC_ROUTE);
  
  /* clean up TR_NAME data, which are not managed by talloc */
  if (body->trust_router != NULL)
    tr_free_name(body->trust_router);
  if (body->next_hop != NULL)
    tr_free_name(body->next_hop);
  return 0;
}

static TRP_INFOREC_DATA *trp_inforec_route_new(TALLOC_CTX *mem_ctx)
{
  TRP_INFOREC_DATA *new_data=talloc(mem_ctx, TRP_INFOREC_DATA);
  TRP_INFOREC_ROUTE *new_rec=NULL;

  if (new_data==NULL)
    return NULL;

  new_rec=talloc(new_data, TRP_INFOREC_ROUTE);
  if (new_rec == NULL) {
    talloc_free(new_data);
    new_data=NULL;
  } else {
    new_rec->trust_router=NULL;
    new_rec->next_hop=NULL;
    new_rec->next_hop_port=0;
    new_rec->metric=TRP_METRIC_INFINITY;
    new_rec->interval=0;
    talloc_set_destructor((void *)new_rec, trp_inforec_route_destructor);
    new_data->route=new_rec;
  }
    
  return new_data;
}


static int trp_inforec_comm_destructor(void *obj)
{
  TRP_INFOREC_COMM *rec=talloc_get_type_abort(obj, TRP_INFOREC_COMM);
  if (rec->owner_realm!=NULL)
    tr_free_name(rec->owner_realm);
  if (rec->owner_contact!=NULL)
    tr_free_name(rec->owner_contact);
  if (rec->provenance!=NULL)
    json_decref(rec->provenance);
  return 0;
}

static TRP_INFOREC_DATA *trp_inforec_comm_new(TALLOC_CTX *mem_ctx)
{
  TRP_INFOREC_DATA *new_data=talloc(mem_ctx, TRP_INFOREC_DATA);
  TRP_INFOREC_COMM *new_rec=NULL;

  if (new_data==NULL)
    return NULL;

  new_rec=talloc(new_data, TRP_INFOREC_COMM);
  if (new_rec==NULL) {
    talloc_free(new_data);
    new_data=NULL;
  } else {
    new_rec->comm_type=TR_COMM_UNKNOWN;
    new_rec->role=TR_ROLE_UNKNOWN;
    new_rec->apcs=NULL;
    new_rec->owner_realm=NULL;
    new_rec->owner_contact=NULL;
    new_rec->expiration_interval=0;
    new_rec->provenance=NULL;
    new_rec->interval=0;
    talloc_set_destructor((void *)new_rec, trp_inforec_comm_destructor);
    new_data->comm=new_rec;
  }

  return new_data;
}

TRP_INFOREC *trp_inforec_get_next(TRP_INFOREC *rec)
{
  if (rec!=NULL)
    return rec->next;
  else
    return NULL;
}

static TRP_INFOREC *trp_inforec_get_tail(TRP_INFOREC *rec)
{
  while ((rec->next)!=NULL)
    rec=trp_inforec_get_next(rec);
  return rec;
}

void trp_inforec_set_next(TRP_INFOREC *rec, TRP_INFOREC *next_rec)
{
  if (rec !=NULL)
    rec->next=next_rec;
}

TRP_INFOREC_TYPE trp_inforec_get_type(TRP_INFOREC *rec)
{
  if (rec!=NULL)
    return rec->type;
  else
    return TRP_INFOREC_TYPE_UNKNOWN;
}

void trp_inforec_set_type(TRP_INFOREC *rec, TRP_INFOREC_TYPE type)
{
  if (rec!=NULL)
    rec->type=type;
}

TR_NAME *trp_inforec_get_trust_router(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data->route!=NULL)
      return rec->data->route->trust_router;
    break;
  default:
    break;
  }
  return NULL;
}

TR_NAME *trp_inforec_dup_trust_router(TRP_INFOREC *rec)
{
  return tr_dup_name(trp_inforec_get_trust_router(rec));
}

TRP_RC trp_inforec_set_trust_router(TRP_INFOREC *rec, TR_NAME *trust_router)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data->route!=NULL) {
      rec->data->route->trust_router=trust_router;
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

/* TODO: need to return hostname/port --jlr */
TR_NAME *trp_inforec_get_next_hop(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data->route!=NULL)
      return rec->data->route->next_hop;
    break;
  default:
    break;
  }
  return NULL;
}

TR_NAME *trp_inforec_dup_next_hop(TRP_INFOREC *rec)
{
  return tr_dup_name(trp_inforec_get_next_hop(rec));
}

TRP_RC trp_inforec_set_next_hop(TRP_INFOREC *rec, TR_NAME *next_hop)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data->route==NULL)
      return TRP_ERROR;
    rec->data->route->next_hop=next_hop;
    break;
  case TRP_INFOREC_TYPE_COMMUNITY:
    /* next hop not used for community records */
    break;
  default:
    break;
  }
  return TRP_SUCCESS;
}

unsigned int trp_inforec_get_metric(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data->route!=NULL)
      return rec->data->route->metric;
    break;
  default:
    break;
  }
  return TRP_METRIC_INVALID;
}

TRP_RC trp_inforec_set_metric(TRP_INFOREC *rec, unsigned int metric)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data->route!=NULL) {
      rec->data->route->metric=metric;
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

unsigned int trp_inforec_get_interval(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data->route!=NULL)
      return rec->data->route->interval;
    break;
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL)
      return rec->data->comm->interval;
    break;
  default:
    break;
  }
  return TRP_INTERVAL_INVALID;
}

TRP_RC trp_inforec_set_interval(TRP_INFOREC *rec, unsigned int interval)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data->route!=NULL) {
      rec->data->route->interval=interval;
      return TRP_SUCCESS;
    }
    break;
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL) {
      rec->data->comm->interval=interval;
      return TRP_SUCCESS;
    }
  default:
    break;
  }
  return TRP_ERROR;
}

time_t trp_inforec_get_exp_interval(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL)
      return rec->data->comm->expiration_interval;
    break;
  default:
    break;
  }
  return 0;
}

TRP_RC trp_inforec_set_exp_interval(TRP_INFOREC *rec, time_t expint)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL) {
      rec->data->comm->expiration_interval=expint;
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

TR_COMM_TYPE trp_inforec_get_comm_type(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL)
      return rec->data->comm->comm_type;
    break;
  default:
    break;
  }
  return TR_COMM_UNKNOWN;
}

TRP_RC trp_inforec_set_comm_type(TRP_INFOREC *rec, TR_COMM_TYPE type)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL) {
      rec->data->comm->comm_type=type;
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

TR_REALM_ROLE trp_inforec_get_role(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL)
      return rec->data->comm->role;
    break;
  default:
    break;
  }
  return TR_ROLE_UNKNOWN;
}

TRP_RC trp_inforec_set_role(TRP_INFOREC *rec, TR_REALM_ROLE role)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL) {
      rec->data->comm->role=role;
      return TRP_SUCCESS;
      break;
    }
  default:
    break;
  }
  return TRP_ERROR;
}

TR_APC *trp_inforec_get_apcs(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL)
      return rec->data->comm->apcs;
    break;
  default:
    break;
  }
  return NULL;
}

TRP_RC trp_inforec_set_apcs(TRP_INFOREC *rec, TR_APC *apcs)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL) {
      rec->data->comm->apcs=apcs;
      talloc_steal(rec, apcs);
      return TRP_SUCCESS;
    }
    break;

  default:
    break;
  }
  return TRP_ERROR;
}

TR_NAME *trp_inforec_get_owner_realm(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL)
      return rec->data->comm->owner_realm;
    break;
  default:
    break;
  }
  return NULL;
}

TRP_RC trp_inforec_set_owner_realm(TRP_INFOREC *rec, TR_NAME *name)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL) {
      rec->data->comm->owner_realm=name;
      return TRP_SUCCESS;
  default:
    break;
    }
    break;
  }
  return TRP_ERROR;
}

TR_NAME *trp_inforec_get_owner_contact(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL)
      return rec->data->comm->owner_contact;
    break;
  default:
    break;
  }
  return NULL;
}

TRP_RC trp_inforec_set_owner_contact(TRP_INFOREC *rec, TR_NAME *name)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL) {
      rec->data->comm->owner_contact=name;
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

/* caller needs to incref the output if they're going to hang on to it */
json_t *trp_inforec_get_provenance(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL)
      return rec->data->comm->provenance;
    break;
  default:
    break;
  }
  return NULL;
}

/* increments the reference count */
TRP_RC trp_inforec_set_provenance(TRP_INFOREC *rec, json_t *prov)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (rec->data->comm!=NULL) {
      if (rec->data->comm->provenance!=NULL)
        json_decref(rec->data->comm->provenance);
      rec->data->comm->provenance=prov;
      json_incref(prov);
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

static TRP_RC trp_inforec_add_to_provenance(TRP_INFOREC *rec, TR_NAME *name)
{
  json_t *jname=NULL;

  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    /* no provenance list */
    break;
  case TRP_INFOREC_TYPE_COMMUNITY:
    jname=tr_name_to_json_string(name);
    if (jname==NULL)
      return TRP_ERROR;
    if (rec->data->comm->provenance==NULL) {
      rec->data->comm->provenance=json_array();
      if (rec->data->comm->provenance==NULL) {
        json_decref(jname);
        return TRP_ERROR;
      }
    }
    if (0!=json_array_append_new(rec->data->comm->provenance, jname)) {
      json_decref(jname);
      return TRP_ERROR;
    }
    break;
  default:
    break;
  }
  return TRP_SUCCESS;
}

TR_NAME *trp_inforec_dup_origin(TRP_INFOREC *rec)
{
  TR_NAME *origin=NULL;
  json_t *prov=trp_inforec_get_provenance(rec);
  const char *s=NULL;

  if (prov==NULL)
    return NULL;

  s=json_string_value(json_array_get(prov, 0));
  if (s==NULL) {
    tr_debug("trp_inforec_dup_origin: empty origin in provenance list.");
    return NULL;
  }
  origin=tr_new_name(s);
  return origin;
}

/* generic record type */
TRP_INFOREC *trp_inforec_new(TALLOC_CTX *mem_ctx, TRP_INFOREC_TYPE type)
{
  TRP_INFOREC *new_rec=talloc(mem_ctx, TRP_INFOREC);
  TRP_INFOREC_DATA *data=NULL;
  struct trp_inforec_type_entry *dtype=get_trp_inforec_type_entry(type);

  if ((new_rec != NULL) && (dtype->type != TRP_INFOREC_TYPE_UNKNOWN)) {
    trp_inforec_set_type(new_rec, type);
    trp_inforec_set_next(new_rec, NULL);
    if (dtype->allocate!=NULL) {
      data=dtype->allocate(new_rec);
      if (data!=NULL)
        new_rec->data=data;
      else {
        talloc_free(new_rec);
        return NULL;
      }
    }
  }
  return new_rec;
}

void trp_inforec_free(TRP_INFOREC *rec)
{
  if (rec!=NULL)
    talloc_free(rec);
}

static int trp_upd_destructor(void *object)
{
  TRP_UPD *upd=talloc_get_type_abort(object, TRP_UPD);
  if (upd->realm!=NULL)
    tr_free_name(upd->realm);
  if (upd->comm!=NULL)
    tr_free_name(upd->comm);
  if (upd->peer!=NULL)
    tr_free_name(upd->peer);
  return 0;
}

TRP_UPD *trp_upd_new(TALLOC_CTX *mem_ctx)
{
  TRP_UPD *new_body=talloc(mem_ctx, TRP_UPD);

  if (new_body!=NULL) {
    new_body->realm=NULL;
    new_body->comm=NULL;
    new_body->records=NULL;
    new_body->peer=NULL;
    talloc_set_destructor((void *)new_body, trp_upd_destructor);
  }
  return new_body;
}

void trp_upd_free(TRP_UPD *update)
{
  if (update!=NULL)
    talloc_free(update);
}

TRP_INFOREC *trp_upd_get_inforec(TRP_UPD *upd)
{
  if (upd!=NULL)
    return upd->records;
  else
    return NULL;
}

void trp_upd_set_inforec(TRP_UPD *upd, TRP_INFOREC *rec)
{
  if (upd!=NULL)
    upd->records=rec;
}

void trp_upd_add_inforec(TRP_UPD *upd, TRP_INFOREC *rec)
{
  tr_debug("trp_upd_add_inforec: adding record.");
  if (upd->records==NULL)
    upd->records=rec;
  else
    trp_inforec_set_next(trp_inforec_get_tail(upd->records), rec);
  talloc_steal(upd, rec);
}

TR_NAME *trp_upd_get_realm(TRP_UPD *upd)
{
  return upd->realm;
}

TR_NAME *trp_upd_dup_realm(TRP_UPD *upd)
{
  return tr_dup_name(upd->realm);
}

void trp_upd_set_realm(TRP_UPD *upd, TR_NAME *realm)
{
  if (upd->realm!=NULL)
    tr_free_name(upd->realm);
  upd->realm=realm;
}

TR_NAME *trp_upd_get_comm(TRP_UPD *upd)
{
  return upd->comm;
}

TR_NAME *trp_upd_dup_comm(TRP_UPD *upd)
{
  return tr_dup_name(upd->comm);
}

void trp_upd_set_comm(TRP_UPD *upd, TR_NAME *comm)
{
  if (upd->comm!=NULL)
    tr_free_name(upd->comm);
  upd->comm=comm;
}

TR_NAME *trp_upd_get_peer(TRP_UPD *upd)
{
  return upd->peer;
}

TR_NAME *trp_upd_dup_peer(TRP_UPD *upd)
{
  return tr_dup_name(upd->peer);
}

void trp_upd_set_peer(TRP_UPD *upd, TR_NAME *peer)
{
  upd->peer=peer;
}

void trp_upd_set_next_hop(TRP_UPD *upd, const char *hostname, unsigned int port)
{
  TRP_INFOREC *rec=NULL;
  TR_NAME *cpy=NULL;
  
  for (rec=trp_upd_get_inforec(upd); rec!=NULL; rec=trp_inforec_get_next(rec)) {
    if (trp_inforec_set_next_hop(rec, cpy=tr_new_name(hostname)) != TRP_SUCCESS) {
      tr_err("trp_upd_set_next_hop: error setting next hop.");
      tr_free_name(cpy);
    }
  }
}

void trp_upd_add_to_provenance(TRP_UPD *upd, TR_NAME *name)
{
  TRP_INFOREC *rec=NULL;

  /* add it to all inforecs */
  for (rec=trp_upd_get_inforec(upd); rec!=NULL; rec=trp_inforec_get_next(rec)) {
    if (TRP_SUCCESS!=trp_inforec_add_to_provenance(rec, name))
      tr_err("trp_upd_set_peer: error adding peer to provenance list.");
  }
}

/* pretty print */
static void trp_inforec_route_print(TRP_INFOREC_DATA *data)
{
  if (data->route!=NULL) {
    printf("     trust_router=%.*s\n     metric=%d\n     interval=%d]\n",
           data->route->trust_router->len, data->route->trust_router->buf,
           data->route->metric, data->route->interval);
  }
}

static void trp_inforec_comm_print(TRP_INFOREC_DATA *data)
{
  if (data->comm!=NULL) {
    printf("     type=%s\n     role=%s\n     owner=%.*s\n     contact=%.*s]\n",
           tr_comm_type_to_str(data->comm->comm_type),
           tr_realm_role_to_str(data->comm->role),
           data->comm->owner_realm->len, data->comm->owner_realm->buf,
           data->comm->owner_contact->len, data->comm->owner_contact->buf);
    /* TODO: print apcs */
  }
}
