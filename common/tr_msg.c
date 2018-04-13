/*
 * Copyright (c) 2012-2014 , JANET(UK)
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
#include <mon_internal.h>
#include <trp_internal.h>
#include <tr_msg.h>
#include <tr_name_internal.h>
#include <trust_router/tr_constraint.h>
#include <trust_router/tr_dh.h>
#include <tr_debug.h>

/* JSON helpers */
/* Read attribute attr from msg as an integer. Returns nonzero on error. */
static int tr_msg_get_json_integer(json_t *jmsg, const char *attr, int *dest)
{
  json_t *obj;

  obj=json_object_get(jmsg, attr);
  if (obj == NULL) {
    return -1;
  }
  /* check type */
  if (!json_is_integer(obj)) {
    return -1;
  }

  (*dest)=json_integer_value(obj);
  return 0;
}

/* Read attribute attr from msg as a string. Copies string into mem_ctx context so jmsg can
 * be destroyed safely. Returns nonzero on error. */
static TRP_RC tr_msg_get_json_string(json_t *jmsg, const char *attr, char **dest, TALLOC_CTX *mem_ctx)
{
  json_t *obj;

  obj=json_object_get(jmsg, attr);
  if (obj == NULL)
    return TRP_ERROR;

  /* check type */
  if (!json_is_string(obj))
    return TRP_ERROR;

  *dest=talloc_strdup(mem_ctx, json_string_value(obj));
  if (*dest==NULL)
    return TRP_ERROR;

  return TRP_SUCCESS;
}

enum msg_type tr_msg_get_msg_type(TR_MSG *msg) 
{
  return msg->msg_type;
}

void tr_msg_set_msg_type(TR_MSG *msg, enum msg_type type)
{
  msg->msg_type = type;
}

TID_REQ *tr_msg_get_req(TR_MSG *msg)
{
  if (msg->msg_type == TID_REQUEST)
    return (TID_REQ *)msg->msg_rep;
  return NULL;
}

void tr_msg_set_req(TR_MSG *msg, TID_REQ *req)
{
  msg->msg_rep = req;
  msg->msg_type = TID_REQUEST;
}

TID_RESP *tr_msg_get_resp(TR_MSG *msg)
{
  if (msg->msg_type == TID_RESPONSE)
    return (TID_RESP *)msg->msg_rep;
  return NULL;
}

void tr_msg_set_resp(TR_MSG *msg, TID_RESP *resp)
{
  msg->msg_rep = resp;
  msg->msg_type = TID_RESPONSE;
}

MON_REQ *tr_msg_get_mon_req(TR_MSG *msg)
{
  if (msg->msg_type == MON_REQUEST)
    return (MON_REQ *)msg->msg_rep;
  return NULL;
}

void tr_msg_set_mon_req(TR_MSG *msg, MON_REQ *req)
{
  msg->msg_rep = req;
  msg->msg_type = MON_REQUEST;
}

MON_RESP *tr_msg_get_mon_resp(TR_MSG *msg)
{
  if (msg->msg_type == MON_RESPONSE)
    return (MON_RESP *)msg->msg_rep;
  return NULL;
}

void tr_msg_set_mon_resp(TR_MSG *msg, MON_RESP *resp)
{
  msg->msg_rep = resp;
  msg->msg_type = MON_RESPONSE;
}

TRP_UPD *tr_msg_get_trp_upd(TR_MSG *msg)
{
  if (msg->msg_type == TRP_UPDATE)
    return (TRP_UPD *)msg->msg_rep;
  return NULL;
}

void tr_msg_set_trp_upd(TR_MSG *msg, TRP_UPD *update)
{
  msg->msg_rep=update;
  talloc_steal(NULL, update); /* should attach to msg, but TR_MSG not usually talloc'ed */
  msg->msg_type=TRP_UPDATE;
}

TRP_REQ *tr_msg_get_trp_req(TR_MSG *msg)
{
  if (msg->msg_type == TRP_REQUEST)
    return (TRP_REQ *)msg->msg_rep;
  return NULL;
}

void tr_msg_set_trp_req(TR_MSG *msg, TRP_REQ *req)
{
  msg->msg_rep=req;
  msg->msg_type=TRP_REQUEST;
}

static json_t *tr_msg_encode_dh(DH *dh)
{
  json_t *jdh = NULL;
  json_t *jbn = NULL;
  char *s=NULL;

  if ((!dh) || (!dh->p) || (!dh->g) || (!dh->pub_key))
    return NULL;

  jdh = json_object();

  jbn = json_string(s=BN_bn2hex(dh->p));
  OPENSSL_free(s);
  json_object_set_new(jdh, "dh_p", jbn);

  jbn = json_string(s=BN_bn2hex(dh->g));
  OPENSSL_free(s);
  json_object_set_new(jdh, "dh_g", jbn);

  jbn = json_string(s=BN_bn2hex(dh->pub_key));
  OPENSSL_free(s);
  json_object_set_new(jdh, "dh_pub_key", jbn);

  return jdh;
}

static DH *tr_msg_decode_dh(json_t *jdh)
{
  DH *dh = NULL;
  json_t *jp = NULL;
  json_t *jg = NULL;
  json_t *jpub_key = NULL;

  if (!(dh=tr_dh_new())) {
    tr_crit("tr_msg_decode_dh(): Error allocating DH structure.");
    return NULL;
  }
 
  /* store required fields from dh object */
  if ((NULL == (jp = json_object_get(jdh, "dh_p"))) ||
      (NULL == (jg = json_object_get(jdh, "dh_g"))) ||
      (NULL == (jpub_key = json_object_get(jdh, "dh_pub_key")))) {
    tr_debug("tr_msg_decode_dh(): Error parsing dh_info.");
    tr_dh_destroy(dh);
    return NULL;
  }

  BN_hex2bn(&(dh->p), json_string_value(jp));
  BN_hex2bn(&(dh->g), json_string_value(jg));
  BN_hex2bn(&(dh->pub_key), json_string_value(jpub_key));

  return dh;
}

static json_t * tr_msg_encode_tidreq(TID_REQ *req)
{
  json_t *jreq = NULL;
  json_t *jstr = NULL;

  if ((!req) || (!req->rp_realm) || (!req->realm) || !(req->comm))
    return NULL;

  assert(jreq = json_object());

  jstr = tr_name_to_json_string(req->rp_realm);
  json_object_set_new(jreq, "rp_realm", jstr);

  jstr = tr_name_to_json_string(req->realm);
  json_object_set_new(jreq, "target_realm", jstr);

  jstr = tr_name_to_json_string(req->comm);
  json_object_set_new(jreq, "community", jstr);
  
  if (req->orig_coi) {
    jstr = tr_name_to_json_string(req->orig_coi);
    json_object_set_new(jreq, "orig_coi", jstr);
  }

  json_object_set_new(jreq, "dh_info", tr_msg_encode_dh(req->tidc_dh));

  if (req->cons)
    json_object_set(jreq, "constraints", (json_t *) req->cons);

  if (req->path)
    json_object_set(jreq, "path", req->path);
  if (req->expiration_interval)
    json_object_set_new(jreq, "expiration_interval",
			json_integer(req->expiration_interval));
  
  return jreq;
}

static TID_REQ *tr_msg_decode_tidreq(json_t *jreq)
{
  TID_REQ *treq = NULL;
  json_t *jrp_realm = NULL;
  json_t *jrealm = NULL;
  json_t *jcomm = NULL;
  json_t *jorig_coi = NULL;
  json_t *jdh = NULL;
  json_t *jpath = NULL;
  json_t *jexpire_interval = NULL;

  if (!(treq =tid_req_new())) {
    tr_crit("tr_msg_decode_tidreq(): Error allocating TID_REQ structure.");
    return NULL;
  }
 
  /* store required fields from request */
  if ((NULL == (jrp_realm = json_object_get(jreq, "rp_realm"))) ||
      (NULL == (jrealm = json_object_get(jreq, "target_realm"))) ||
      (NULL == (jcomm = json_object_get(jreq, "community")))) {
    tr_notice("tr_msg_decode(): Error parsing required fields.");
    tid_req_free(treq);
    return NULL;
  }

  jpath = json_object_get(jreq, "path");
  jexpire_interval = json_object_get(jreq, "expiration_interval");

  treq->rp_realm = tr_new_name((char *)json_string_value(jrp_realm));
  treq->realm = tr_new_name((char *)json_string_value(jrealm));
  treq->comm = tr_new_name((char *)json_string_value(jcomm));

  /* Get DH Info from the request */
  if (NULL == (jdh = json_object_get(jreq, "dh_info"))) {
    tr_debug("tr_msg_decode(): Error parsing dh_info.");
    tid_req_free(treq);
    return NULL;
  }
  treq->tidc_dh = tr_msg_decode_dh(jdh);

  /* store optional "orig_coi" field */
  if (NULL != (jorig_coi = json_object_get(jreq, "orig_coi"))) {
    treq->orig_coi = tr_new_name((char *)json_string_value(jorig_coi));
  }

  treq->cons = (TR_CONSTRAINT_SET *) json_object_get(jreq, "constraints");
  if (treq->cons) {
    if (!tr_constraint_set_validate(treq->cons)) {
      tr_debug("Constraint set validation failed");
    tid_req_free(treq);
    return NULL;
    }
    json_incref((json_t *) treq->cons);
    tid_req_cleanup_json(treq, (json_t *) treq->cons);
  }
  if (jpath) {
    json_incref(jpath);
    treq->path = jpath;
    tid_req_cleanup_json(treq, jpath);
  }
  if (jexpire_interval)
    treq->expiration_interval = json_integer_value(jexpire_interval);
  
  return treq;
}

static json_t *tr_msg_encode_one_server(TID_SRVR_BLK *srvr)
{
  json_t *jsrvr = NULL;
  json_t *jstr = NULL;
  gchar *time_str = g_time_val_to_iso8601(&srvr->key_expiration);

  tr_debug("Encoding one server.");

  jsrvr = json_object();

  jstr = json_string(srvr->aaa_server_addr);
  json_object_set_new(jsrvr, "server_addr", jstr);

  json_object_set_new(jsrvr,
		      "key_expiration", json_string(time_str));
  g_free(time_str);
  /* Server DH Block */
  jstr = tr_name_to_json_string(srvr->key_name);
  json_object_set_new(jsrvr, "key_name", jstr);
  json_object_set_new(jsrvr, "server_dh", tr_msg_encode_dh(srvr->aaa_server_dh));
  if (srvr->path)
    /* The path is owned by the srvr, so grab an extra ref*/
    json_object_set(jsrvr, "path", (json_t *)(srvr->path));
  return jsrvr;
}

static int tr_msg_decode_one_server(json_t *jsrvr, TID_SRVR_BLK *srvr) 
{
  json_t *jsrvr_addr = NULL;
  json_t *jsrvr_kn = NULL;
  json_t *jsrvr_dh = NULL;
  json_t *jsrvr_expire = NULL;

  if (jsrvr == NULL)
    return -1;


  if ((NULL == (jsrvr_addr = json_object_get(jsrvr, "server_addr"))) ||
      (NULL == (jsrvr_kn = json_object_get(jsrvr, "key_name"))) ||
      (NULL == (jsrvr_dh = json_object_get(jsrvr, "server_dh")))) {
    tr_notice("tr_msg_decode_one_server(): Error parsing required fields.");
    return -1;
  }

  srvr->aaa_server_addr=talloc_strdup(srvr, json_string_value(jsrvr_addr));
  srvr->key_name = tr_new_name((char *)json_string_value(jsrvr_kn));
  srvr->aaa_server_dh = tr_msg_decode_dh(jsrvr_dh);
  tid_srvr_blk_set_path(srvr, (TID_PATH *) json_object_get(jsrvr, "path"));
  jsrvr_expire = json_object_get(jsrvr, "key_expiration");
  if (jsrvr_expire && json_is_string(jsrvr_expire)) {
    if (!g_time_val_from_iso8601(json_string_value(jsrvr_expire),
				 &srvr->key_expiration))
      tr_notice("Key expiration %s cannot be parsed", json_string_value(jsrvr_expire));
  }
  
  return 0;
}

static json_t *tr_msg_encode_servers(TID_RESP *resp)
{
  json_t *jservers = NULL;
  json_t *jsrvr = NULL;
  TID_SRVR_BLK *srvr = NULL;
  size_t index;

  jservers = json_array();

  tid_resp_servers_foreach(resp, srvr, index) {
    if ((NULL == (jsrvr = tr_msg_encode_one_server(srvr))) ||
	(-1 == json_array_append_new(jservers, jsrvr))) {
      return NULL;
    }
  }

  //  tr_debug("tr_msg_encode_servers(): servers contains:");
  //  tr_debug("%s", json_dumps(jservers, 0));
  return jservers;
}

static TID_SRVR_BLK *tr_msg_decode_servers(TALLOC_CTX *mem_ctx, json_t *jservers)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TID_SRVR_BLK *servers=NULL;
  TID_SRVR_BLK *new_srvr=NULL;
  json_t *jsrvr;
  size_t i, num_servers;

  num_servers = json_array_size(jservers);
  tr_debug("tr_msg_decode_servers(): Number of servers = %u.", (unsigned) num_servers);
  
  if (0 == num_servers) {
    tr_debug("tr_msg_decode_servers(): Server array is empty."); 
    goto cleanup;
  }

  for (i = 0; i < num_servers; i++) {
    jsrvr = json_array_get(jservers, i);

    new_srvr=tid_srvr_blk_new(tmp_ctx);
    if (new_srvr==NULL) {
      servers=NULL; /* it's all in tmp_ctx, so we can just let go */
      goto cleanup;
    }
    
    if (0 != tr_msg_decode_one_server(jsrvr, new_srvr)) {
      servers=NULL; /* it's all in tmp_ctx, so we can just let go */
      goto cleanup;
    }

    tid_srvr_blk_add(servers, new_srvr);
  }

  talloc_steal(mem_ctx, servers);

cleanup:
  talloc_free(tmp_ctx);
  return servers;
}

static json_t * tr_msg_encode_tidresp(TID_RESP *resp)
{
  json_t *jresp = NULL;
  json_t *jstr = NULL;
  json_t *jservers = NULL;

  if ((!resp) || (!resp->rp_realm) || (!resp->realm) || !(resp->comm))
    return NULL;

  jresp = json_object();

  if (TID_ERROR == resp->result) {
    jstr = json_string("error");
    json_object_set_new(jresp, "result", jstr);
    if (resp->err_msg) {
      jstr = tr_name_to_json_string(resp->err_msg);
      json_object_set_new(jresp, "err_msg", jstr);
    }
  }
  else {
    jstr = json_string("success");
    json_object_set_new(jresp, "result", jstr);
  }

  jstr = tr_name_to_json_string(resp->rp_realm);
  json_object_set_new(jresp, "rp_realm", jstr);

  jstr = tr_name_to_json_string(resp->realm);
  json_object_set_new(jresp, "target_realm", jstr);

  jstr = tr_name_to_json_string(resp->comm);
  json_object_set_new(jresp, "comm", jstr);

  if (resp->orig_coi) {
    jstr = tr_name_to_json_string(resp->orig_coi);
    json_object_set_new(jresp, "orig_coi", jstr);
  }

  if (NULL == resp->servers) {
    tr_debug("tr_msg_encode_tidresp(): No servers to encode.");
  }
  else {
    jservers = tr_msg_encode_servers(resp);
    json_object_set_new(jresp, "servers", jservers);
  }
  if (resp->error_path)
    json_object_set(jresp, "error_path", resp->error_path);
  
  
  return jresp;
}

static TID_RESP *tr_msg_decode_tidresp(json_t *jresp)
{
  TID_RESP *tresp = NULL;
  json_t *jresult = NULL;
  json_t *jrp_realm = NULL;
  json_t *jrealm = NULL;
  json_t *jcomm = NULL;
  json_t *jorig_coi = NULL;
  json_t *jservers = NULL;
  json_t *jerr_msg = NULL;

  if (!(tresp=tid_resp_new(NULL))) {
    tr_crit("tr_msg_decode_tidresp(): Error allocating TID_RESP structure.");
    return NULL;
  }
 

  /* store required fields from response */
  if ((NULL == (jresult = json_object_get(jresp, "result"))) ||
      (!json_is_string(jresult)) ||
      (NULL == (jrp_realm = json_object_get(jresp, "rp_realm"))) ||
      (!json_is_string(jrp_realm)) ||
      (NULL == (jrealm = json_object_get(jresp, "target_realm"))) ||
      (!json_is_string(jrealm)) ||
      (NULL == (jcomm = json_object_get(jresp, "comm"))) ||
      (!json_is_string(jcomm))) {
    tr_debug("tr_msg_decode_tidresp(): Error parsing response.");
    talloc_free(tresp);
    return NULL;
  }

  if (0 == (strcmp(json_string_value(jresult), "success"))) {
    tr_debug("tr_msg_decode_tidresp(): Success! result = %s.", json_string_value(jresult));
    if ((NULL != (jservers = json_object_get(jresp, "servers"))) ||
	(!json_is_array(jservers))) {
      tresp->servers = tr_msg_decode_servers(tresp, jservers); 
    } 
    else {
      talloc_free(tresp);
      return NULL;
    }
    tresp->result = TID_SUCCESS;
  }
  else {
    tresp->result = TID_ERROR;
    tr_debug("tr_msg_decode_tidresp(): Error! result = %s.", json_string_value(jresult));
    if ((NULL != (jerr_msg = json_object_get(jresp, "err_msg"))) ||
	(!json_is_string(jerr_msg))) {
      tresp->err_msg = tr_new_name(json_string_value(jerr_msg));
    } else
      tresp->err_msg = tr_new_name("No error message set.");

    if (NULL !=(tresp->error_path = json_object_get(jresp, "error_path")))
      json_incref(tresp->error_path);
  }

  tresp->rp_realm = tr_new_name(json_string_value(jrp_realm));
  tresp->realm = tr_new_name(json_string_value(jrealm));
  tresp->comm = tr_new_name(json_string_value(jcomm));

  /* store optional "orig_coi" field */
  if ((NULL != (jorig_coi = json_object_get(jresp, "orig_coi"))) &&
      (!json_is_object(jorig_coi))) {
    tresp->orig_coi = tr_new_name(json_string_value(jorig_coi));
  }
     
  return tresp;
}


/* Information records for TRP update msg 
 * requires that jrec already be allocated */
static TRP_RC tr_msg_encode_inforec_route(json_t *jrec, TRP_INFOREC *rec)
{
  json_t *jstr=NULL;
  json_t *jint=NULL;
  char *s=NULL;

  if (rec==NULL)
    return TRP_BADTYPE;

  if (trp_inforec_get_trust_router(rec)==NULL)
    return TRP_ERROR;

  s=tr_name_strdup(trp_inforec_get_trust_router(rec));
  if (s==NULL)
    return TRP_NOMEM;
  jstr=json_string(s);
  free(s);s=NULL;
  if(jstr==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "trust_router", jstr);

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
  int num=0;

  rc=tr_msg_get_json_string(jrecord, "trust_router", &s, tmp_ctx);
  if (rc != TRP_SUCCESS)
    goto cleanup;
  if (TRP_SUCCESS!=trp_inforec_set_trust_router(rec, tr_new_name(s))) {
    rc=TRP_ERROR;
    goto cleanup;
  }
  talloc_free(s); s=NULL;

  trp_inforec_set_next_hop(rec, NULL); /* make sure this is null (filled in later) */

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
static json_t *tr_msg_encode_trp_upd(TRP_UPD *update)
{
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
static TRP_UPD *tr_msg_decode_trp_upd(TALLOC_CTX *mem_ctx, json_t *jupdate)
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

static json_t *tr_msg_encode_trp_req(TRP_REQ *req)
{
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

static TRP_REQ *tr_msg_decode_trp_req(TALLOC_CTX *mem_ctx, json_t *jreq)
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

char *tr_msg_encode(TALLOC_CTX *mem_ctx, TR_MSG *msg)
{
  json_t *jmsg=NULL;
  json_t *jmsg_type=NULL;
  char *encoded_tmp=NULL;
  char *encoded=NULL;
  TID_RESP *tidresp=NULL;
  TID_REQ *tidreq=NULL;
  TRP_UPD *trpupd=NULL;
  TRP_REQ *trpreq=NULL;
  MON_REQ *monreq=NULL;
  MON_RESP *monresp=NULL;

  /* TBD -- add error handling */
  jmsg = json_object();

  switch (msg->msg_type) 
    {
    case TID_REQUEST:
      jmsg_type = json_string("tid_request");
      json_object_set_new(jmsg, "msg_type", jmsg_type);
      tidreq=tr_msg_get_req(msg);
      json_object_set_new(jmsg, "msg_body", tr_msg_encode_tidreq(tidreq));
      break;

    case TID_RESPONSE:
      jmsg_type = json_string("tid_response");
      json_object_set_new(jmsg, "msg_type", jmsg_type);
      tidresp=tr_msg_get_resp(msg);
      json_object_set_new(jmsg, "msg_body", tr_msg_encode_tidresp(tidresp));
      break;

      case TRP_UPDATE:
        jmsg_type = json_string("trp_update");
        json_object_set_new(jmsg, "msg_type", jmsg_type);
        trpupd=tr_msg_get_trp_upd(msg);
        json_object_set_new(jmsg, "msg_body", tr_msg_encode_trp_upd(trpupd));
        break;

      case TRP_REQUEST:
        jmsg_type = json_string("trp_request");
        json_object_set_new(jmsg, "msg_type", jmsg_type);
        trpreq=tr_msg_get_trp_req(msg);
        json_object_set_new(jmsg, "msg_body", tr_msg_encode_trp_req(trpreq));
        break;

      case MON_REQUEST:
        jmsg_type = json_string("mon_request");
        json_object_set_new(jmsg, "msg_type", jmsg_type);
        monreq=tr_msg_get_mon_req(msg);
        json_object_set_new(jmsg, "msg_body", mon_req_encode(monreq));
        break;

      case MON_RESPONSE:
        jmsg_type = json_string("mon_response");
        json_object_set_new(jmsg, "msg_type", jmsg_type);
        monresp=tr_msg_get_mon_resp(msg);
        json_object_set_new(jmsg, "msg_body", mon_resp_encode(monresp));
        break;

      default:
      json_decref(jmsg);
      return NULL;
    }

  /* We should perhaps use json_set_alloc_funcs to automatically use talloc, but for
   * now, we'll encode to a malloc'ed buffer, then copy that to a talloc'ed buffer. */
  encoded_tmp=json_dumps(jmsg, 0);                // malloc'ed version
  json_decref(jmsg);                              // free the JSON structure
  encoded = talloc_strdup(mem_ctx, encoded_tmp);  // get the talloc'ed version
  free(encoded_tmp);                              // free the malloc'ed version

  tr_debug("tr_msg_encode: outgoing msg=%s", encoded);
  return encoded;
}

TR_MSG *tr_msg_decode(const char *jbuf, size_t buflen)
{
  TR_MSG *msg=NULL;
  json_t *jmsg = NULL;
  json_error_t rc;
  json_t *jtype=NULL;
  json_t *jbody=NULL;
  const char *mtype = NULL;

  if (NULL == (jmsg = json_loadb(jbuf, buflen, JSON_DISABLE_EOF_CHECK, &rc))) {
    tr_debug("tr_msg_decode(): error loading object");
    return NULL;
  }

  if (!(msg = malloc(sizeof(TR_MSG)))) {
    tr_debug("tr_msg_decode(): Error allocating TR_MSG structure.");
    json_decref(jmsg);
    return NULL;
  }
 
  memset(msg, 0, sizeof(TR_MSG));

  if ((NULL == (jtype = json_object_get(jmsg, "msg_type"))) ||
      (NULL == (jbody = json_object_get(jmsg, "msg_body")))) {
    tr_debug("tr_msg_decode(): Error parsing message header.");
    json_decref(jmsg);
    tr_msg_free_decoded(msg);
    return NULL;
  }

  mtype = json_string_value(jtype);

  if (0 == strcmp(mtype, "tid_request")) {
    msg->msg_type = TID_REQUEST;
    tr_msg_set_req(msg, tr_msg_decode_tidreq(jbody));
  }
  else if (0 == strcmp(mtype, "tid_response")) {
    msg->msg_type = TID_RESPONSE;
    tr_msg_set_resp(msg, tr_msg_decode_tidresp(jbody));
  }
  else if (0 == strcmp(mtype, "trp_update")) {
    msg->msg_type = TRP_UPDATE;
    tr_msg_set_trp_upd(msg, tr_msg_decode_trp_upd(NULL, jbody)); /* null talloc context for now */
  }
  else if (0 == strcmp(mtype, "trp_request")) {
    msg->msg_type = TRP_UPDATE;
    tr_msg_set_trp_req(msg, tr_msg_decode_trp_req(NULL, jbody)); /* null talloc context for now */
  }
  else if (0 == strcmp(mtype, "mon_request")) {
    msg->msg_type = MON_REQUEST;
    tr_msg_set_mon_req(msg, mon_req_decode(NULL, jbody));
  }
  /* We do not currently handle monitoring responses */
//  else if (0 == strcmp(mtype, "mon_response")) {
//    msg->msg_type = MON_RESPONSE;
//    tr_msg_set_mon_resp(msg, mon_resp_decode(NULL, jbody));
//  }
  else {
    msg->msg_type = TR_UNKNOWN;
    msg->msg_rep = NULL;
  }

  json_decref(jmsg);

  return msg;
}

void tr_msg_free_encoded(char *jmsg)
{
  if (jmsg)
    free (jmsg);
}

void tr_msg_free_decoded(TR_MSG *msg)
{
  if (msg) {
    if (msg->msg_rep!=NULL) {
      switch (msg->msg_type) {
        case TID_REQUEST:
          tid_req_free(tr_msg_get_req(msg));
          break;
        case TID_RESPONSE:
          tid_resp_free(tr_msg_get_resp(msg));
          break;
        case TRP_UPDATE:
          trp_upd_free(tr_msg_get_trp_upd(msg));
          break;
        case TRP_REQUEST:
          trp_req_free(tr_msg_get_trp_req(msg));
        default:
          break;
        case MON_REQUEST:
          mon_req_free(tr_msg_get_mon_req(msg));
          break;
        case MON_RESPONSE:
          mon_resp_free(tr_msg_get_mon_resp(msg));
          break;
      }
    }
    free (msg);
  }
}
