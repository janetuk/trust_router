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
static json_t *tr_msg_encode_tidreq(void *msg_rep);
static void *tr_msg_decode_tidreq(TALLOC_CTX *mem_ctx, json_t *jreq);
static json_t * tr_msg_encode_tidresp(void *msg_rep);
static void *tr_msg_decode_tidresp(TALLOC_CTX *mem_ctx, json_t *jresp);

/* Global handle for message types */
static struct {
  TR_MSG_TYPE tid_request;
  TR_MSG_TYPE tid_response;
} tid_msg_type = {TR_MSG_TYPE_UNKNOWN, TR_MSG_TYPE_UNKNOWN};

/* Must call this before sending or receiving TID messages */
int tr_msg_tid_init(void)
{
  int result = 1; /* 1 is success */

  if (tid_msg_type.tid_request == TR_MSG_TYPE_UNKNOWN) {
    tid_msg_type.tid_request = tr_msg_register_type("tid_request",
                                                    tr_msg_decode_tidreq,
                                                    tr_msg_encode_tidreq);
    if (tid_msg_type.tid_request == TR_MSG_TYPE_UNKNOWN) {
      tr_err("tr_msg_tid_init: unable to register TID request message type");
      result = 0;
    }
  }

  if (tid_msg_type.tid_response == TR_MSG_TYPE_UNKNOWN) {
    tid_msg_type.tid_response = tr_msg_register_type("tid_response",
                                                     tr_msg_decode_tidresp,
                                                     tr_msg_encode_tidresp);
    if (tid_msg_type.tid_response == TR_MSG_TYPE_UNKNOWN) {
      tr_err("tr_msg_tid_init: unable to register TID response message type");
      result = 0;
    }
  }

  return result;
}

/**
 * Set the message payload to a TID request
 *
 * Sets the message type
 */
void tr_msg_set_req(TR_MSG *msg, TID_REQ *req)
{
  tr_msg_set_msg_type(msg, tid_msg_type.tid_request);
  tr_msg_set_rep(msg, req);
}

/**
 * Get the TID request from a generic TR_MSG
 *
 * Returns null if the message is not a TID_REQUEST
 */
TID_REQ *tr_msg_get_req(TR_MSG *msg)
{
  if (tr_msg_get_msg_type(msg) == tid_msg_type.tid_request)
    return (TID_REQ *) tr_msg_get_rep(msg);
  return NULL;
}

/**
 * Set the message payload to a TID response
 *
 * Sets the message type
 */
void tr_msg_set_resp(TR_MSG *msg, TID_RESP *resp)
{
  tr_msg_set_msg_type(msg, tid_msg_type.tid_response);
  tr_msg_set_rep(msg, resp);
}

/**
 * Get the TID response from a generic TR_MSG
 *
 * Returns null if the message is not a TID response
 */
TID_RESP *tr_msg_get_resp(TR_MSG *msg)
{
  if (tr_msg_get_msg_type(msg) == tid_msg_type.tid_response)
    return (TID_RESP *) tr_msg_get_rep(msg);
  return NULL;
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


static json_t *tr_msg_encode_tidreq(void *msg_rep)
{
  TID_REQ *req = (TID_REQ *) msg_rep;
  json_t *jreq = NULL;
  json_t *jstr = NULL;

  if ((!req) || (!req->rp_realm) || (!req->realm) || !(req->comm))
    return NULL;

  jreq = json_object();
  assert(jreq);

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

  if (tid_req_get_request_id(req)) {
    jstr = tr_name_to_json_string(tid_req_get_request_id(req));
    json_object_set_new(jreq, "request_id", jstr);
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

static void *tr_msg_decode_tidreq(TALLOC_CTX *mem_ctx, json_t *jreq)
{
  TID_REQ *treq = NULL;
  json_t *jrp_realm = NULL;
  json_t *jrealm = NULL;
  json_t *jcomm = NULL;
  json_t *jorig_coi = NULL;
  json_t *jrequest_id = NULL;
  json_t *jdh = NULL;
  json_t *jpath = NULL;
  json_t *jexpire_interval = NULL;

  if (!(treq =tid_req_new())) {
    tr_crit("tr_msg_decode_tidreq(): Error allocating TID_REQ structure.");
    return NULL;
  }
  talloc_steal(mem_ctx, treq);

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

  treq->rp_realm = tr_new_name(json_string_value(jrp_realm));
  treq->realm = tr_new_name(json_string_value(jrealm));
  treq->comm = tr_new_name(json_string_value(jcomm));

  /* Get DH Info from the request */
  if (NULL == (jdh = json_object_get(jreq, "dh_info"))) {
    tr_debug("tr_msg_decode(): Error parsing dh_info.");
    tid_req_free(treq);
    return NULL;
  }
  treq->tidc_dh = tr_msg_decode_dh(jdh);

  /* store optional "orig_coi" field */
  if (NULL != (jorig_coi = json_object_get(jreq, "orig_coi"))) {
    treq->orig_coi = tr_new_name(json_string_value(jorig_coi));
  }

  /* store optional "request_id" field */
  if (NULL != (jrequest_id = json_object_get(jreq, "request_id"))) {
    tid_req_set_request_id(treq, tr_new_name(json_string_value(jrequest_id)));
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

  return (void *)treq;
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

static json_t * tr_msg_encode_tidresp(void *msg_rep)
{
  TID_RESP *resp = (TID_RESP *) msg_rep;
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

  if (tid_resp_get_request_id(resp)) {
    jstr = tr_name_to_json_string(tid_resp_get_request_id(resp));
    json_object_set_new(jresp, "request_id", jstr);
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

static void *tr_msg_decode_tidresp(TALLOC_CTX *mem_ctx, json_t *jresp)
{
  TID_RESP *tresp = NULL;
  json_t *jresult = NULL;
  json_t *jrp_realm = NULL;
  json_t *jrealm = NULL;
  json_t *jcomm = NULL;
  json_t *jorig_coi = NULL;
  json_t *jrequest_id = NULL;
  json_t *jservers = NULL;
  json_t *jerr_msg = NULL;

  if (!(tresp=tid_resp_new(mem_ctx))) {
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
      json_is_string(jorig_coi)) {
    tresp->orig_coi = tr_new_name(json_string_value(jorig_coi));
  }

  /* store optional "request_id" field */
  if ((NULL != (jrequest_id = json_object_get(jresp, "request_id"))) &&
      json_is_string(jrequest_id)) {
    tid_resp_set_request_id(tresp, tr_new_name(json_string_value(jrequest_id)));
  }

  return (void *) tresp;
}
