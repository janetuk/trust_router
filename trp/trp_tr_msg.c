/*
 * Copyright (c) 2012-2018 , JANET(UK)
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/crypto.h>
#include <jansson.h>
#include <assert.h>
#include <talloc.h>

#include <tr_apc.h>
#include <tr_comm.h>
#include <trp_internal.h>
#include <mon_internal.h>
#include <tr_msg.h>
#include <tr_util.h>
#include <tr_name_internal.h>
#include <trust_router/tr_constraint.h>
#include <trust_router/tr_dh.h>
#include <tr_debug.h>
#include <tr_inet_util.h>

/* Prototypes */
static json_t *tr_msg_encode_trp_upd(void *msg_rep);
static void *tr_msg_decode_trp_upd(TALLOC_CTX *mem_ctx, json_t *jupdate);
static json_t *tr_msg_encode_trp_req(void *msg_rep);
static void *tr_msg_decode_trp_req(TALLOC_CTX *mem_ctx, json_t *jreq);

/* Global handle for message types */
static struct {
  TR_MSG_TYPE trp_update;
  TR_MSG_TYPE trp_request;
} trp_msg_type = {TR_MSG_TYPE_UNKNOWN, TR_MSG_TYPE_UNKNOWN};

/* Must call this before sending or receiving TRP messages */
int tr_msg_trp_init(void)
{
  int result = 1; /* 1 is success */

  if (trp_msg_type.trp_update == TR_MSG_TYPE_UNKNOWN) {
    trp_msg_type.trp_update = tr_msg_register_type("trp_update",
                                                   tr_msg_decode_trp_upd,
                                                   tr_msg_encode_trp_upd);
    if (trp_msg_type.trp_update == TR_MSG_TYPE_UNKNOWN) {
      tr_err("tr_msg_trp_init: unable to register TRP update message type");
      result = 0;
    }
  }

  if (trp_msg_type.trp_request == TR_MSG_TYPE_UNKNOWN) {
    trp_msg_type.trp_request = tr_msg_register_type("trp_request",
                                                    tr_msg_decode_trp_req,
                                                    tr_msg_encode_trp_req);
    if (trp_msg_type.trp_request == TR_MSG_TYPE_UNKNOWN) {
      tr_err("tr_msg_trp_init: unable to register TRP request message type");
      result = 0;
    }
  }

  return result;
}

/**
 * Set the message payload to a TRP request
 *
 * Sets the message type
 */
void tr_msg_set_trp_req(TR_MSG *msg, TRP_REQ *req)
{
  tr_msg_set_msg_type(msg, trp_msg_type.trp_request);
  tr_msg_set_rep(msg, req);
}

/**
 * Get the TRP request from a generic TR_MSG
 *
 * Returns null if the message is not a TRP request
 */
TRP_REQ *tr_msg_get_trp_req(TR_MSG *msg)
{
  if (tr_msg_get_msg_type(msg) == trp_msg_type.trp_request)
    return (TRP_REQ *) tr_msg_get_rep(msg);
  return NULL;
}

/**
 * Set the message payload to a TRP update
 *
 * Sets the message type
 */
void tr_msg_set_trp_upd(TR_MSG *msg, TRP_UPD *upd)
{
  tr_msg_set_msg_type(msg, trp_msg_type.trp_update);
  tr_msg_set_rep(msg, upd);
}

/**
 * Get the TRP update from a generic TR_MSG
 *
 * Returns null if the message is not a TRP update
 */
TRP_UPD *tr_msg_get_trp_upd(TR_MSG *msg)
{
  if (tr_msg_get_msg_type(msg) == trp_msg_type.trp_update)
    return (TRP_UPD *) tr_msg_get_rep(msg);
  return NULL;
}

/* JSON helpers */
/* Read attribute attr from msg as an integer. */
static TRP_RC tr_msg_get_json_integer(json_t *jmsg, const char *attr, int *dest)
{
  json_t *obj;

  obj=json_object_get(jmsg, attr);
  if (obj == NULL) {
    return TRP_MISSING;
  }
  /* check type */
  if (!json_is_integer(obj)) {
    return TRP_BADTYPE;
  }

  (*dest)=json_integer_value(obj);
  return TRP_SUCCESS;
}

/* Read attribute attr from msg as a string. Copies string into mem_ctx context so jmsg can
 * be destroyed safely. Returns nonzero on error. */
static TRP_RC tr_msg_get_json_string(json_t *jmsg, const char *attr, char **dest, TALLOC_CTX *mem_ctx)
{
  json_t *obj;

  obj=json_object_get(jmsg, attr);
  if (obj == NULL)
    return TRP_MISSING;

  /* check type */
  if (!json_is_string(obj))
    return TRP_BADTYPE;

  *dest=talloc_strdup(mem_ctx, json_string_value(obj));
  if (*dest==NULL)
    return TRP_NOMEM;

  return TRP_SUCCESS;
}

static json_t *hostname_and_port_to_json(TR_NAME *hostname, int port)
{
  char *s_hostname = tr_name_strdup(hostname);
  char *s;
  json_t *j;

  if (s_hostname == NULL)
    return NULL;

  s = talloc_asprintf(NULL, "%s:%d", s_hostname, port);
  free(s_hostname);

  if (s == NULL)
    return NULL;

  j = json_string(s);
  talloc_free(s);

  return j;
}

/* Information records for TRP update msg
 * requires that jrec already be allocated */
static TRP_RC tr_msg_encode_inforec_route(json_t *jrec, TRP_INFOREC *rec)
{
  json_t *jstr=NULL;
  json_t *jint=NULL;

  if (rec==NULL)
    return TRP_BADTYPE;

  if (trp_inforec_get_trust_router(rec)==NULL)
    return TRP_ERROR;

  jstr=hostname_and_port_to_json(trp_inforec_get_trust_router(rec),
                                 trp_inforec_get_trust_router_port(rec));
  if(jstr==NULL)
    return TRP_NOMEM;
  json_object_set_new(jrec, "trust_router", jstr);

  jstr=hostname_and_port_to_json(trp_inforec_get_next_hop(rec),
                                 trp_inforec_get_next_hop_port(rec));
  if(jstr==NULL)
    return TRP_NOMEM;
  json_object_set_new(jrec, "next_hop", jstr);

  jint=json_integer(trp_inforec_get_metric(rec));
  if(jint==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "metric", jint);

  jint=json_integer(trp_inforec_get_interval(rec));
  if(jint==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "interval", jint);

  return TRP_SUCCESS;
}

/* returns a json array */
static json_t *tr_msg_encode_apcs(TR_APC *apcs)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_APC_ITER *iter=tr_apc_iter_new(tmp_ctx);
  TR_APC *apc=NULL;
  json_t *jarray=NULL;
  json_t *jid=NULL;

  if (iter==NULL)
    goto cleanup;

  jarray=json_array();
  if (jarray==NULL)
    goto cleanup;

  for (apc=tr_apc_iter_first(iter, apcs); apc!=NULL; apc=tr_apc_iter_next(iter)) {
    jid=tr_name_to_json_string(tr_apc_get_id(apc));
    if ((jid==NULL) || (json_array_append_new(jarray, jid)!=0)) {
      json_decref(jarray);
      jarray=NULL;
      goto cleanup;
    }
  }

cleanup:
  talloc_free(tmp_ctx);
  return jarray;
}

static TR_APC *tr_msg_decode_apcs(TALLOC_CTX *mem_ctx, json_t *jarray, TRP_RC *rc)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  size_t ii=0;
  TR_APC *apc_list=NULL;
  TR_APC *new=NULL;
  json_t *jstr=NULL;

  *rc=TRP_ERROR;

  for (ii=0; ii<json_array_size(jarray); ii++) {
    jstr=json_array_get(jarray, ii);
    new=tr_apc_new(tmp_ctx);
    if ((jstr==NULL) || (new==NULL) || (!json_is_string(jstr))) {
      apc_list=NULL; /* these are all in tmp_ctx, so they'll still get cleaned up */
      goto cleanup;
    }

    tr_apc_set_id(new, tr_new_name(json_string_value(jstr)));
    if (tr_apc_get_id(new)==NULL) {
      apc_list=NULL; /* these are all in tmp_ctx, so they'll still get cleaned up */
      goto cleanup;
    }

    tr_apc_add(apc_list, new);
  }

  *rc=TRP_SUCCESS;

  if (apc_list!=NULL)
    talloc_steal(mem_ctx, apc_list);

cleanup:
  talloc_free(tmp_ctx);
  return apc_list;
}

static TRP_RC tr_msg_encode_inforec_comm(json_t *jrec, TRP_INFOREC *rec)
{
  json_t *jstr=NULL;
  json_t *jint=NULL;
  json_t *japcs=NULL;
  const char *sconst=NULL;
  TR_COMM_TYPE commtype=TR_COMM_UNKNOWN;

  if (rec==NULL)
    return TRP_BADTYPE;

  commtype=trp_inforec_get_comm_type(rec);
  if (commtype==TR_COMM_UNKNOWN) {
    tr_notice("tr_msg_encode_inforec_comm: unknown community type.");
    return TRP_ERROR;
  }
  sconst=tr_comm_type_to_str(commtype);
  if (sconst==NULL)
    return TRP_ERROR;
  jstr=json_string(sconst);
  if(jstr==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "type", jstr);

  sconst=tr_realm_role_to_str(trp_inforec_get_role(rec));
  if (sconst==NULL) {
    tr_notice("tr_msg_encode_inforec_comm: unknown realm role.");
    return TRP_ERROR;
  }
  jstr=json_string(sconst);
  if(jstr==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "role", jstr);

  japcs=tr_msg_encode_apcs(trp_inforec_get_apcs(rec));
  if (japcs==NULL) {
    tr_notice("tr_msg_encode_inforec_comm: error encoding APCs.");
    return TRP_ERROR;
  }
  json_object_set_new(jrec, "apcs", japcs);


  if (trp_inforec_get_owner_realm(rec)!=NULL) {
    jstr=tr_name_to_json_string(trp_inforec_get_owner_realm(rec));
    if(jstr==NULL)
      return TRP_ERROR;
    json_object_set_new(jrec, "owner_realm", jstr);
  }

  if (trp_inforec_get_owner_contact(rec)!=NULL) {
    jstr=tr_name_to_json_string(trp_inforec_get_owner_contact(rec));
    if(jstr==NULL)
      return TRP_ERROR;
    json_object_set_new(jrec, "owner_contact", jstr);
  }

  json_object_set(jrec, "provenance", trp_inforec_get_provenance(rec));

  jint=json_integer(trp_inforec_get_interval(rec));
  if(jint==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "interval", jint);

  return TRP_SUCCESS;
}

static json_t *tr_msg_encode_inforec(TRP_INFOREC *rec)
{
  json_t *jrec=NULL;
  json_t *jstr=NULL;

  if ((rec==NULL) || (trp_inforec_get_type(rec)==TRP_INFOREC_TYPE_UNKNOWN))
    return NULL;

  jrec=json_object();
  if (jrec==NULL)
    return NULL;

  jstr=json_string(trp_inforec_type_to_string(trp_inforec_get_type(rec)));
  if (jstr==NULL) {
    json_decref(jrec);
    return NULL;
  }
  json_object_set_new(jrec, "record_type", jstr);

  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (TRP_SUCCESS!=tr_msg_encode_inforec_route(jrec, rec)) {
      json_decref(jrec);
      return NULL;
    }
    break;
  case TRP_INFOREC_TYPE_COMMUNITY:
    if (TRP_SUCCESS!=tr_msg_encode_inforec_comm(jrec, rec)) {
      json_decref(jrec);
      return NULL;
    }
    break;
  default:
    json_decref(jrec);
    return NULL;
  }
  return jrec;
}

static TRP_RC tr_msg_decode_trp_inforec_route(json_t *jrecord, TRP_INFOREC *rec)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_RC rc=TRP_ERROR;
  char *s=NULL;
  TR_NAME *name;
  char *hostname;
  int port;
  int num=0;

  /* get the trust router */
  rc=tr_msg_get_json_string(jrecord, "trust_router", &s, tmp_ctx);
  if (rc != TRP_SUCCESS)
    goto cleanup;

  hostname = tr_parse_host(tmp_ctx, s, &port);
  if ((NULL == hostname)
      || (NULL == (name = tr_new_name(hostname)))
      || (port < 0)) {
    rc = TRP_ERROR;
    goto cleanup;
  }
  talloc_free(s); s=NULL;
  talloc_free(hostname);

  if (port == 0)
    port = TRP_PORT;

  if (TRP_SUCCESS!= trp_inforec_set_trust_router(rec, name, port)) {
    rc=TRP_ERROR;
    goto cleanup;
  }

  /* Now do the next hop. If it's not present, use the trust_router for backward
   * compatibility */
  switch(tr_msg_get_json_string(jrecord, "next_hop", &s, tmp_ctx)) {
    case TRP_SUCCESS:
      /* we got a next_hop field */
      hostname = tr_parse_host(tmp_ctx, s, &port);
      if ((hostname == NULL)
          || (NULL == (name = tr_new_name(hostname)))
          || (port < 0)) {
        rc = TRP_ERROR;
        goto cleanup;
      }
      break;

    case TRP_MISSING:
      /* no next_hop field; use the trust router */
      name = tr_dup_name(trp_inforec_get_trust_router(rec));
      if (name == NULL) {
        rc = TRP_ERROR;
        goto cleanup;
      }
      break;

    default:
      /* something went wrong */
      rc = TRP_ERROR;
      goto cleanup;
  }
  talloc_free(s); s=NULL;

  if (port == 0)
    port = TID_PORT;

  if (TRP_SUCCESS!= trp_inforec_set_next_hop(rec, name, port)) {
    rc=TRP_ERROR;
    goto cleanup;
  }

  rc=tr_msg_get_json_integer(jrecord, "metric", &num);
  if ((rc != TRP_SUCCESS) || (TRP_SUCCESS!=trp_inforec_set_metric(rec,num)))
    goto cleanup;

  rc=tr_msg_get_json_integer(jrecord, "interval", &num);
  if ((rc != TRP_SUCCESS) || (TRP_SUCCESS!=trp_inforec_set_interval(rec,num)))
    goto cleanup;

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

static TRP_RC tr_msg_decode_trp_inforec_comm(json_t *jrecord, TRP_INFOREC *rec)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_RC rc=TRP_ERROR;
  char *s=NULL;
  int num=0;
  TR_APC *apcs=NULL;

  rc=tr_msg_get_json_string(jrecord, "type", &s, tmp_ctx);
  if (rc != TRP_SUCCESS)
    goto cleanup;
  if (TRP_SUCCESS!=trp_inforec_set_comm_type(rec, tr_comm_type_from_str(s))) {
    rc=TRP_ERROR;
    goto cleanup;
  }
  talloc_free(s); s=NULL;

  rc=tr_msg_get_json_string(jrecord, "role", &s, tmp_ctx);
  if (rc != TRP_SUCCESS)
    goto cleanup;
  if (TRP_SUCCESS!=trp_inforec_set_role(rec, tr_realm_role_from_str(s))) {
    rc=TRP_ERROR;
    goto cleanup;
  }
  talloc_free(s); s=NULL;

  apcs=tr_msg_decode_apcs(rec, json_object_get(jrecord, "apcs"), &rc);
  if (rc!=TRP_SUCCESS) {
    rc=TRP_ERROR;
    goto cleanup;
  }
  trp_inforec_set_apcs(rec, apcs);

  rc=tr_msg_get_json_integer(jrecord, "interval", &num);
  tr_debug("tr_msg_decode_trp_inforec_comm: interval=%u", num);
  if ((rc != TRP_SUCCESS) || (TRP_SUCCESS!=trp_inforec_set_interval(rec,num)))
    goto cleanup;

  trp_inforec_set_provenance(rec, json_object_get(jrecord, "provenance"));

  /* optional */
  rc=tr_msg_get_json_string(jrecord, "owner_realm", &s, tmp_ctx);
  if (rc == TRP_SUCCESS) {
    if (TRP_SUCCESS!=trp_inforec_set_owner_realm(rec, tr_new_name(s))) {
      rc=TRP_ERROR;
      goto cleanup;
    }
    if (s!=NULL) {
      talloc_free(s);
      s=NULL;
    }
  }

  rc=tr_msg_get_json_string(jrecord, "owner_contact", &s, tmp_ctx);
  if (rc == TRP_SUCCESS) {
    if (TRP_SUCCESS!=trp_inforec_set_owner_contact(rec, tr_new_name(s))) {
      rc=TRP_ERROR;
      goto cleanup;
    }
    if (s!=NULL) {
      talloc_free(s);
      s=NULL;
    }
  }

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

/* decode a single record */
static TRP_INFOREC *tr_msg_decode_trp_inforec(TALLOC_CTX *mem_ctx, json_t *jrecord)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_INFOREC_TYPE rectype;
  TRP_INFOREC *rec=NULL;
  TRP_RC rc=TRP_ERROR;
  char *s=NULL;

  if (TRP_SUCCESS!=tr_msg_get_json_string(jrecord, "record_type", &s, tmp_ctx))
    goto cleanup;

  rectype=trp_inforec_type_from_string(s);
  talloc_free(s); s=NULL;

  rec=trp_inforec_new(tmp_ctx, rectype);
  if (rec==NULL) {
    rc=TRP_NOMEM;
    goto cleanup;
  }

  tr_debug("tr_msg_decode_trp_inforec: '%s' record found.", trp_inforec_type_to_string(rec->type));

  switch(trp_inforec_get_type(rec)) {
  case TRP_INFOREC_TYPE_ROUTE:
    rc=tr_msg_decode_trp_inforec_route(jrecord, rec);
    break;
  case TRP_INFOREC_TYPE_COMMUNITY:
    rc=tr_msg_decode_trp_inforec_comm(jrecord, rec);
    break;
  default:
    rc=TRP_UNSUPPORTED;
    goto cleanup;
  }

  talloc_steal(mem_ctx, rec);
  rc=TRP_SUCCESS;

cleanup:
  if (rc != TRP_SUCCESS) {
    trp_inforec_free(rec);
    rec=NULL;
  }
  talloc_free(tmp_ctx);
  return rec;
}

/* TRP update msg */
static json_t *tr_msg_encode_trp_upd(void *msg_rep)
{
  TRP_UPD *update = (TRP_UPD *) msg_rep;
  json_t *jupdate=NULL;
  json_t *jrecords=NULL;
  json_t *jrec=NULL;
  json_t *jstr=NULL;
  TRP_INFOREC *rec;
  char *s=NULL;

  if (update==NULL)
    return NULL;

  jupdate=json_object();
  if (jupdate==NULL)
    return NULL;

  s=tr_name_strdup(trp_upd_get_comm(update));
  if (s==NULL) {
    json_decref(jupdate);
    return NULL;
  }
  jstr=json_string(s);
  free(s);s=NULL;
  if(jstr==NULL) {
    json_decref(jupdate);
    return NULL;
  }
  json_object_set_new(jupdate, "community", jstr);

  s=tr_name_strdup(trp_upd_get_realm(update));
  if (s==NULL) {
    json_decref(jupdate);
    return NULL;
  }
  jstr=json_string(s);
  free(s);s=NULL;
  if(jstr==NULL) {
    json_decref(jupdate);
    return NULL;
  }
  json_object_set_new(jupdate, "realm", jstr);

  jrecords=json_array();
  if (jrecords==NULL) {
    json_decref(jupdate);
    return NULL;
  }
  json_object_set_new(jupdate, "records", jrecords); /* jrecords now a "borrowed" reference */
  for (rec=trp_upd_get_inforec(update); rec!=NULL; rec=trp_inforec_get_next(rec)) {
    tr_debug("tr_msg_encode_trp_upd: encoding inforec.");
    jrec=tr_msg_encode_inforec(rec);
    if (jrec==NULL) {
      json_decref(jupdate); /* also decs jrecords and any elements */
      return NULL;
    }
    if (0!=json_array_append_new(jrecords, jrec)) {
      json_decref(jupdate); /* also decs jrecords and any elements */
      json_decref(jrec); /* this one did not get added so dec explicitly */
      return NULL;
    }
  }

  return jupdate;
}

/* Creates a linked list of records in the msg->body talloc context.
 * An error will be returned if any unparseable records are encountered.
 */
static void *tr_msg_decode_trp_upd(TALLOC_CTX *mem_ctx, json_t *jupdate)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  json_t *jrecords=NULL;
  size_t ii=0;
  TRP_UPD *update=NULL;
  TRP_INFOREC *new_rec=NULL;
  TRP_INFOREC *list_tail=NULL;
  char *s=NULL;
  TR_NAME *name;
  TRP_RC rc=TRP_ERROR;

  update=trp_upd_new(tmp_ctx);
  if (update==NULL) {
    rc=TRP_NOMEM;
    goto cleanup;
  }

  rc=tr_msg_get_json_string(jupdate, "community", &s, tmp_ctx);
  if (rc != TRP_SUCCESS) {
    tr_debug("tr_msg_decode_trp_upd: no community in TRP update message.");
    rc=TRP_NOPARSE;
    goto cleanup;
  }
  name=tr_new_name(s);
  if (name==NULL) {
    tr_debug("tr_msg_decode_trp_upd: could not allocate community name.");
    rc=TRP_NOMEM;
    goto cleanup;
  }
  talloc_free(s); s=NULL;
  trp_upd_set_comm(update, name);

  rc=tr_msg_get_json_string(jupdate, "realm", &s, tmp_ctx);
  if (rc != TRP_SUCCESS) {
    tr_debug("tr_msg_decode_trp_upd: no realm in TRP update message.");
    rc=TRP_NOPARSE;
    goto cleanup;
  }
  name=tr_new_name(s);
  if (name==NULL) {
    tr_debug("tr_msg_decode_trp_upd: could not allocate realm name.");
    rc=TRP_NOMEM;
    goto cleanup;
  }
  talloc_free(s); s=NULL;
  trp_upd_set_realm(update, name);

  jrecords=json_object_get(jupdate, "records");
  if ((jrecords==NULL) || (!json_is_array(jrecords))) {
    rc=TRP_NOPARSE;
    goto cleanup;
  }

  tr_debug("tr_msg_decode_trp_upd: found %d records", json_array_size(jrecords));
  /* process the array */
  for (ii=0; ii<json_array_size(jrecords); ii++) {
    new_rec=tr_msg_decode_trp_inforec(update, json_array_get(jrecords, ii));
    if (new_rec==NULL) {
      rc=TRP_NOPARSE;
      goto cleanup;
    }

    if (list_tail==NULL)
      trp_upd_set_inforec(update, new_rec); /* first is a special case */
    else
      trp_inforec_set_next(list_tail, new_rec);

    list_tail=new_rec;
  }

  /* Succeeded. Move new allocations into the correct talloc context */
  talloc_steal(mem_ctx, update);
  rc=TRP_SUCCESS;

cleanup:
  talloc_free(tmp_ctx);
  if (rc!=TRP_SUCCESS)
    return NULL;
  return update;
}

static json_t *tr_msg_encode_trp_req(void *msg_rep)
{
  TRP_REQ *req = (TRP_REQ *) msg_rep;
  json_t *jbody=NULL;
  json_t *jstr=NULL;
  char *s=NULL;

  if (req==NULL)
    return NULL;

  jbody=json_object();
  if (jbody==NULL)
    return NULL;

  if ((NULL==trp_req_get_comm(req))
     || (NULL==trp_req_get_realm(req))) {
    json_decref(jbody);
    return NULL;
  }

  s=tr_name_strdup(trp_req_get_comm(req)); /* ensures null termination */
  if (s==NULL) {
    json_decref(jbody);
    return NULL;
  }
  jstr=json_string(s);
  free(s); s=NULL;
  if (jstr==NULL) {
    json_decref(jbody);
    return NULL;
  }
  json_object_set_new(jbody, "community", jstr);

  s=tr_name_strdup(trp_req_get_realm(req)); /* ensures null termination */
  if (s==NULL) {
    json_decref(jbody);
    return NULL;
  }
  jstr=json_string(s);
  free(s); s=NULL;
  if (jstr==NULL) {
    json_decref(jbody);
    return NULL;
  }
  json_object_set_new(jbody, "realm", jstr);

  return jbody;
}

static void *tr_msg_decode_trp_req(TALLOC_CTX *mem_ctx, json_t *jreq)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_REQ *req=NULL;
  char *s=NULL;
  TRP_RC rc=TRP_ERROR;

  /* check message type and body type for agreement */
  req=trp_req_new(tmp_ctx);
  if (req==NULL) {
    rc=TRP_NOMEM;
    goto cleanup;
  }

  rc=tr_msg_get_json_string(jreq, "community", &s, tmp_ctx);
  if (rc!=TRP_SUCCESS)
    goto cleanup;
  trp_req_set_comm(req, tr_new_name(s));
  talloc_free(s); s=NULL;

  rc=tr_msg_get_json_string(jreq, "realm", &s, tmp_ctx);
  if (rc!=TRP_SUCCESS)
    goto cleanup;
  trp_req_set_realm(req, tr_new_name(s));
  talloc_free(s); s=NULL;

  rc=TRP_SUCCESS;
  talloc_steal(mem_ctx, req);

cleanup:
  talloc_free(tmp_ctx);
  if (rc!=TRP_SUCCESS)
    return NULL;
  return req;
}
