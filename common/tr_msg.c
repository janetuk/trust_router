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

#include <string.h>
#include <openssl/dh.h>
#include <jansson.h>

#include <tr_msg.h>
#include <trust_router/tr_name.h>
#include <trust_router/tid.h>

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
  json_error_t rc;
  json_t *jp = NULL;
  json_t *jg = NULL;
  json_t *jpub_key = NULL;
  int msize;

  if (!(dh = malloc(sizeof(DH)))) {
    fprintf (stderr, "tr_msg_decode_dh(): Error allocating DH structure.\n");
    return NULL;
  }
 
  memset(dh, 0, sizeof(DH));

  /* store required fields from dh object */
  if (((msize = json_object_size(jdh)) < 3) ||
      (NULL == (jp = json_object_get(jdh, "dh_p"))) ||
      (!json_is_string(jp)) ||
      (NULL == (jg = json_object_get(jdh, "dh_g"))) ||
      (!json_is_string(jg)) ||
      (NULL == (jpub_key = json_object_get(jdh, "dh_pub_key"))) ||
      (!json_is_string(jdh))) {
    fprintf (stderr, "tr_msg_decode(): Error parsing message.\n");
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

  jreq = json_object();

  jstr = json_string(req->rp_realm->buf);
  json_object_set_new(jreq, "rp_realm", jstr);

  jstr = json_string(req->realm->buf);
  json_object_set_new(jreq, "target_realm", jstr);

  jstr = json_string(req->comm->buf);
  json_object_set_new(jreq, "community", jstr);

  json_object_set_new(jreq, "dh_info", tr_msg_encode_dh(req->tidc_dh));
  
  return jreq;
}

static TID_REQ *tr_msg_decode_tidreq(json_t *jreq)
{
  TID_REQ *treq = NULL;
  json_error_t rc;
  json_t *jrp_realm = NULL;
  json_t *jrealm = NULL;
  json_t *jcomm = NULL;
  json_t *jorig_coi = NULL;
  json_t *jdh = NULL;
  int msize;

  if (!(treq = malloc(sizeof(TID_REQ)))) {
    fprintf (stderr, "tr_msg_decode_tidreq(): Error allocating TID_REQ structure.\n");
    return NULL;
  }
 
  memset(treq, 0, sizeof(TID_REQ));

  /* store required fields from request */
  if (((msize = json_object_size(jreq)) < 4) ||
      (NULL == (jrp_realm = json_object_get(jreq, "rp_realm"))) ||
      (!json_is_string(jrp_realm)) ||
      (NULL == (jrealm = json_object_get(jreq, "realm"))) ||
      (!json_is_string(jrealm)) ||
      (NULL == (jcomm = json_object_get(jreq, "comm"))) ||
      (!json_is_string(jcomm)) ||
      (NULL == (jdh = json_object_get(jreq, "dh_info"))) ||
      (!json_is_object(jdh))) {
    fprintf (stderr, "tr_msg_decode(): Error parsing message.\n");
    free(treq);
    return NULL;
  }

  treq->rp_realm = tr_new_name((char *)json_string_value(jrp_realm));
  treq->realm = tr_new_name((char *)json_string_value(jrealm));
  treq->comm = tr_new_name((char *)json_string_value(jcomm));
  treq->tidc_dh = tr_msg_decode_dh(jdh);

  /* store optional "orig_coi" field */
  if ((NULL != (jorig_coi = json_object_get(jreq, "orig_coi"))) &&
      (!json_is_object(jorig_coi))) {
    treq->orig_coi = tr_new_name((char *)json_string_value(jorig_coi));
  }

  return treq;
}

static json_t * tr_msg_encode_tidresp(TID_RESP *resp)
{
  json_t *jresp = NULL;
  json_t *jstr = NULL;

  if ((!resp) || (!resp->result) || (!resp->rp_realm) || (!resp->realm) || !(resp->comm))
    return NULL;

  jresp = json_object();

  jstr = json_string(resp->result->buf);
  json_object_set_new(jresp, "result", jstr);

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

  // TBD -- Encode server info.
  
  return jresp;
}

static TID_RESP *tr_msg_decode_tidresp(json_t *jresp)
{
  TID_RESP *tresp = NULL;
  json_error_t rc;
  json_t *jresult = NULL;
  json_t *jrp_realm = NULL;
  json_t *jrealm = NULL;
  json_t *jcomm = NULL;
  json_t *jorig_coi = NULL;
  json_t *jservers = NULL;
  int msize;

  if (!(tresp = malloc(sizeof(TID_RESP)))) {
    fprintf (stderr, "tr_msg_decode_tidresp(): Error allocating TID_RESP structure.\n");
    return NULL;
  }
 
  memset(tresp, 0, sizeof(TID_RESP));

  /* store required fields from request */
  if (((msize = json_object_size(jresp)) < 5) ||
      (NULL == (jresult = json_object_get(jresp, "result"))) ||
      (!json_is_string(jresult)) ||
      (NULL == (jrp_realm = json_object_get(jresp, "rp_realm"))) ||
      (!json_is_string(jrp_realm)) ||
      (NULL == (jrealm = json_object_get(jresp, "realm"))) ||
      (!json_is_string(jrealm)) ||
      (NULL == (jcomm = json_object_get(jresp, "comm"))) ||
      (!json_is_string(jcomm)) ||
      (NULL == (jservers = json_object_get(jresp, "servers"))) ||
      (!json_is_object(jservers))) {
    fprintf (stderr, "tr_msg_decode(): Error parsing message.\n");
    free(tresp);
    return NULL;
  }

  tresp->result = tr_new_name((char *)json_string_value(jresult));
  tresp->rp_realm = tr_new_name((char *)json_string_value(jrp_realm));
  tresp->realm = tr_new_name((char *)json_string_value(jrealm));
  tresp->comm = tr_new_name((char *)json_string_value(jcomm));

  /* store optional "orig_coi" field */
  if ((NULL != (jorig_coi = json_object_get(jresp, "orig_coi"))) &&
      (!json_is_object(jorig_coi))) {
    tresp->orig_coi = tr_new_name((char *)json_string_value(jorig_coi));
  }

  //  Decode server info
  //  tresp->servers = tr_msg_decode_servers(jservers); 
  
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
      jmsg_type = json_string("TIDRequest");
      json_object_set_new(jmsg, "msg_type", jmsg_type);
      json_object_set_new(jmsg, "msg_body", tr_msg_encode_tidreq(msg->tid_req));
      break;

    case TID_RESPONSE:
      jmsg_type = json_string("TIDResponse");
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
  size_t msize;
  json_t *jtype;
  json_t *jbody;
  const char *mtype = NULL;

  if (NULL == (jmsg = json_loadb(jbuf, buflen, 0, &rc))) {
    fprintf (stderr, "tr_msg_decode(): error loading object, rc = %d.\n", rc);
    return NULL;
  }

  if (!(msg = malloc(sizeof(TR_MSG)))) {
    fprintf (stderr, "tr_msg_decode(): Error allocating TR_MSG structure.\n");
    json_decref(jmsg);
    return NULL;
  }
 
  memset(msg, 0, sizeof(TR_MSG));

  if ((2 != (msize = json_object_size(jmsg))) ||
      (NULL == (jtype = json_object_get(jmsg, "msg_type"))) ||
      (!json_is_string(jtype)) ||
      (NULL == (jbody = json_object_get(jmsg, "msg_body"))) ||
      (!json_is_object(jbody))) {
    fprintf (stderr, "tr_msg_decode(): Error parsing message.\n");
    json_decref(jmsg);
    tr_msg_free_decoded(msg);
    return NULL;
  }

  mtype = json_string_value(jtype);

  if (0 == strcmp(mtype, "TIDRequest")) {
    msg->msg_type = TID_REQUEST;
    msg->tid_req = tr_msg_decode_tidreq(jbody);
  }
  else if (0 == strcmp(mtype, "TIDResponse")) {
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


