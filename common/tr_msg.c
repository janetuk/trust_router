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
#include <jansson.h>
#include <assert.h>
#include <talloc.h>


#include <tr_msg.h>
#include <trust_router/tr_name.h>
#include <tid_internal.h>
#include <trust_router/tr_constraint.h>
#include <tr_debug.h>

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
  return msg->tid_req;
}

void tr_msg_set_req(TR_MSG *msg, TID_REQ *req)
{
  msg->tid_req = req;
}

TID_RESP *tr_msg_get_resp(TR_MSG *msg)
{
  return msg->tid_resp;
}

void tr_msg_set_resp(TR_MSG *msg, TID_RESP *resp)
{
  msg->tid_resp = resp;
}

static json_t *tr_msg_encode_dh(DH *dh)
{
  json_t *jdh = NULL;
  json_t *jbn = NULL;

  if ((!dh) || (!dh->p) || (!dh->g) || (!dh->pub_key))
    return NULL;

  jdh = json_object();

  jbn = json_string(BN_bn2hex(dh->p));
  json_object_set_new(jdh, "dh_p", jbn);

  jbn = json_string(BN_bn2hex(dh->g));
  json_object_set_new(jdh, "dh_g", jbn);

  jbn = json_string(BN_bn2hex(dh->pub_key));
  json_object_set_new(jdh, "dh_pub_key", jbn);

  return jdh;
}

static DH *tr_msg_decode_dh(json_t *jdh)
{
  DH *dh = NULL;
  json_t *jp = NULL;
  json_t *jg = NULL;
  json_t *jpub_key = NULL;

  if (!(dh = malloc(sizeof(DH)))) {
    fprintf (stderr, "tr_msg_decode_dh(): Error allocating DH structure.\n");
    return NULL;
  }
 
  memset(dh, 0, sizeof(DH));

  /* store required fields from dh object */
  if ((NULL == (jp = json_object_get(jdh, "dh_p"))) ||
      (NULL == (jg = json_object_get(jdh, "dh_g"))) ||
      (NULL == (jpub_key = json_object_get(jdh, "dh_pub_key")))) {
    fprintf (stderr, "tr_msg_decode_dh(): Error parsing dh_info.\n");
    free(dh);
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

  jstr = json_string(req->rp_realm->buf);
  json_object_set_new(jreq, "rp_realm", jstr);

  jstr = json_string(req->realm->buf);
  json_object_set_new(jreq, "target_realm", jstr);

  jstr = json_string(req->comm->buf);
  json_object_set_new(jreq, "community", jstr);
  
  if (req->orig_coi) {
    jstr = json_string(req->orig_coi->buf);
    json_object_set_new(jreq, "orig_coi", jstr);
  }

  json_object_set_new(jreq, "dh_info", tr_msg_encode_dh(req->tidc_dh));

  if (req->cons)
    json_object_set(jreq, "constraints", (json_t *) req->cons);

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

  if (!(treq =tid_req_new())) {
    fprintf (stderr, "tr_msg_decode_tidreq(): Error allocating TID_REQ structure.\n");
    return NULL;
  }
 
  /* store required fields from request */
  if ((NULL == (jrp_realm = json_object_get(jreq, "rp_realm"))) ||
      (NULL == (jrealm = json_object_get(jreq, "target_realm"))) ||
      (NULL == (jcomm = json_object_get(jreq, "community")))) {
    fprintf (stderr, "tr_msg_decode(): Error parsing required fields.\n");
    tid_req_free(treq);
    return NULL;
  }

  treq->rp_realm = tr_new_name((char *)json_string_value(jrp_realm));
  treq->realm = tr_new_name((char *)json_string_value(jrealm));
  treq->comm = tr_new_name((char *)json_string_value(jcomm));

  /* Get DH Info from the request */
  if (NULL == (jdh = json_object_get(jreq, "dh_info"))) {
    fprintf (stderr, "tr_msg_decode(): Error parsing dh_info.\n");
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
      tr_debug("Constraint set validation failed\n");
    tid_req_free(treq);
    return NULL;
    }
    json_incref((json_t *) treq->cons);
    tid_req_cleanup_json(treq, (json_t *) treq->cons);
  }
  return treq;
}

static json_t *tr_msg_encode_one_server(TID_SRVR_BLK *srvr)
{
  json_t *jsrvr = NULL;
  json_t *jstr = NULL;

  fprintf(stderr, "Encoding one server.\n");

  jsrvr = json_object();

  /* Server IP Address -- TBD handle IPv6 */
  jstr = json_string(inet_ntoa(srvr->aaa_server_addr));
  json_object_set_new(jsrvr, "server_addr", jstr);

  /* Server DH Block */
  jstr = json_string(srvr->key_name->buf);
  json_object_set_new(jsrvr, "key_name", jstr);
  json_object_set_new(jsrvr, "server_dh", tr_msg_encode_dh(srvr->aaa_server_dh));
  
  //  fprintf(stderr,"tr_msg_encode_one_server(): jsrvr contains:\n");
  //  fprintf(stderr,"%s\n", json_dumps(jsrvr, 0));
  return jsrvr;
}

static int tr_msg_decode_one_server(json_t *jsrvr, TID_SRVR_BLK *srvr) 
{
  json_t *jsrvr_addr = NULL;
  json_t *jsrvr_kn = NULL;
  json_t *jsrvr_dh = NULL;

  if (jsrvr == NULL)
    return -1;


  if ((NULL == (jsrvr_addr = json_object_get(jsrvr, "server_addr"))) ||
      (NULL == (jsrvr_kn = json_object_get(jsrvr, "key_name"))) ||
      (NULL == (jsrvr_dh = json_object_get(jsrvr, "server_dh")))) {
    tr_debug("tr_msg_decode_one_server(): Error parsing required fields.\n");
    return -1;
  }
  
  /* TBD -- handle IPv6 Addresses */
  inet_aton(json_string_value(jsrvr_addr), &(srvr->aaa_server_addr));
  srvr->key_name = tr_new_name((char *)json_string_value(jsrvr_kn));
  srvr->aaa_server_dh = tr_msg_decode_dh(jsrvr_dh);
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

  //  fprintf(stderr,"tr_msg_encode_servers(): servers contains:\n");
  //  fprintf(stderr,"%s\n", json_dumps(jservers, 0));
  return jservers;
}

static TID_SRVR_BLK *tr_msg_decode_servers(void * ctx, json_t *jservers) 
{
  TID_SRVR_BLK *servers = NULL;
  json_t *jsrvr;
  size_t i, num_servers;

  num_servers = json_array_size(jservers);
  fprintf(stderr, "tr_msg_decode_servers(): Number of servers = %u.\n", (unsigned) num_servers);
  
  if (0 == num_servers) {
    fprintf(stderr, "tr_msg_decode_servers(): Server array is empty.\n"); 
    return NULL;
  }
    servers = talloc_zero_array(ctx, TID_SRVR_BLK, num_servers);

  for (i = 0; i < num_servers; i++) {
    jsrvr = json_array_get(jservers, i);
    if (0 != tr_msg_decode_one_server(jsrvr, &servers[i])) {
      talloc_free(servers);
      return NULL;
    }


  }

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
      jstr = json_string(resp->err_msg->buf);
      json_object_set_new(jresp, "err_msg", jstr);
    }
  }
  else {
    jstr = json_string("success");
    json_object_set_new(jresp, "result", jstr);
  }

  jstr = json_string(resp->rp_realm->buf);
  json_object_set_new(jresp, "rp_realm", jstr);

  jstr = json_string(resp->realm->buf);
  json_object_set_new(jresp, "target_realm", jstr);

  jstr = json_string(resp->comm->buf);
  json_object_set_new(jresp, "comm", jstr);

  if (resp->orig_coi) {
    jstr = json_string(resp->orig_coi->buf);
    json_object_set_new(jresp, "orig_coi", jstr);
  }

  if (NULL == resp->servers) {
    fprintf(stderr, "tr_msg_encode_tidresp(): No servers to encode.\n");
    return jresp;
  }
  jservers = tr_msg_encode_servers(resp);
  json_object_set_new(jresp, "servers", jservers);
  
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

  if (!(tresp = talloc_zero(NULL, TID_RESP))) {
    fprintf (stderr, "tr_msg_decode_tidresp(): Error allocating TID_RESP structure.\n");
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
    fprintf (stderr, "tr_msg_decode_tidresp(): Error parsing response.\n");
    talloc_free(tresp);
    return NULL;
  }

  if (0 == (strcmp(json_string_value(jresult), "success"))) {
    fprintf(stderr, "tr_msg_decode_tidresp(): Success! result = %s.\n", json_string_value(jresult));
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
    fprintf(stderr, "tr_msg_decode_tidresp(): Error! result = %s.\n", json_string_value(jresult));
    if ((NULL != (jerr_msg = json_object_get(jresp, "err_msg"))) ||
	(!json_is_string(jerr_msg))) {
      tresp->err_msg = tr_new_name((char *)json_string_value(jerr_msg));
    }
  }

  tresp->rp_realm = tr_new_name((char *)json_string_value(jrp_realm));
  tresp->realm = tr_new_name((char *)json_string_value(jrealm));
  tresp->comm = tr_new_name((char *)json_string_value(jcomm));

  /* store optional "orig_coi" field */
  if ((NULL != (jorig_coi = json_object_get(jresp, "orig_coi"))) &&
      (!json_is_object(jorig_coi))) {
    tresp->orig_coi = tr_new_name((char *)json_string_value(jorig_coi));
  }
     
  return tresp;
}

char *tr_msg_encode(TR_MSG *msg) 
{
  json_t *jmsg;
  json_t *jmsg_type;

  /* TBD -- add error handling */
  jmsg = json_object();

  switch (msg->msg_type) 
    {
    case TID_REQUEST:
      jmsg_type = json_string("tid_request");
      json_object_set_new(jmsg, "msg_type", jmsg_type);
      json_object_set_new(jmsg, "msg_body", tr_msg_encode_tidreq(msg->tid_req));
      break;

    case TID_RESPONSE:
      jmsg_type = json_string("tid_response");
      json_object_set_new(jmsg, "msg_type", jmsg_type);
      json_object_set_new(jmsg, "msg_body", tr_msg_encode_tidresp(msg->tid_resp));
      break;

      /* TBD -- Add TR message types */

    default:
      json_decref(jmsg);
      return NULL;
    }
  
  return(json_dumps(jmsg, 0));
}

TR_MSG *tr_msg_decode(char *jbuf, size_t buflen)
{
  TR_MSG *msg;
  json_t *jmsg = NULL;
  json_error_t rc;
  json_t *jtype;
  json_t *jbody;
  const char *mtype = NULL;

  if (NULL == (jmsg = json_loadb(jbuf, buflen, JSON_DISABLE_EOF_CHECK, &rc))) {
    fprintf (stderr, "tr_msg_decode(): error loading object\n");
    return NULL;
  }

  if (!(msg = malloc(sizeof(TR_MSG)))) {
    fprintf (stderr, "tr_msg_decode(): Error allocating TR_MSG structure.\n");
    json_decref(jmsg);
    return NULL;
  }
 
  memset(msg, 0, sizeof(TR_MSG));

  if ((NULL == (jtype = json_object_get(jmsg, "msg_type"))) ||
      (NULL == (jbody = json_object_get(jmsg, "msg_body")))) {
    fprintf (stderr, "tr_msg_decode(): Error parsing message header.\n");
    json_decref(jmsg);
    tr_msg_free_decoded(msg);
    return NULL;
  }

  mtype = json_string_value(jtype);

  if (0 == strcmp(mtype, "tid_request")) {
    msg->msg_type = TID_REQUEST;
    msg->tid_req = tr_msg_decode_tidreq(jbody);
  }
  else if (0 == strcmp(mtype, "tid_response")) {
    msg->msg_type = TID_RESPONSE;
    msg->tid_resp = tr_msg_decode_tidresp(jbody);
  }
  else {
    msg->msg_type = TR_UNKNOWN;
    msg->tid_req = NULL;
  }
  return msg;
}

void tr_msg_free_encoded(char *jmsg)
{
  if (jmsg)
    free (jmsg);
}

void tr_msg_free_decoded(TR_MSG *msg)
{
  if (msg)
    free (msg);
}


