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
#include <tpq.h>
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

  return dh;
}

json_t *tr_msg_encode_tpqreq(TPQ_REQ *req)
{
  json_t *jreq = NULL;
  json_t *jstr = NULL;

  if ((!req) || (!req->rp_realm) || (!req->realm) || !(req->coi))
    return NULL;

  jreq = json_object();

  jstr = json_string(req->rp_realm->buf);
  json_object_set_new(jreq, "rp_realm", jstr);

  jstr = json_string(req->realm->buf);
  json_object_set_new(jreq, "target_realm", jstr);

  jstr = json_string(req->coi->buf);
  json_object_set_new(jreq, "community", jstr);

  json_object_set_new(jreq, "dh_info", tr_msg_encode_dh(req->tpqc_dh));
  
  return jreq;
}

TPQ_REQ *tr_msg_decode_tpqreq(json_t *jreq)
{
  TPQ_REQ *req = NULL;

  return req;
}

json_t *tr_msg_encode_tpqresp(TPQ_RESP *resp)
{
  json_t *jresp = NULL;

  return jresp;
}


TPQ_RESP *tr_msg_decode_tpqresp(json_t *jresp)
{
  TPQ_RESP *resp = NULL;

  return resp;
}

json_t *tr_msg_encode_tidrreq(TIDR_REQ *req)
{
  json_t *jreq = NULL;

  return jreq;

}

TIDR_REQ *tr_msg_decode_tidrreq(json_t *jreq)
{
  TIDR_REQ *req = NULL;

  return req;
}

json_t *tr_msg_encode_tidrresp(TIDR_RESP *resp)
{
  json_t *jresp = NULL;

  return jresp;
}

TIDR_RESP *tr_msg_decode_tidrresp(json_t *jresp)
{
  TIDR_RESP *resp = NULL;

  return resp;
}

char *tr_msg_encode(TR_MSG *msg) 
{
  json_t *jmsg;
  json_t *jmsg_type;

  /* TBD -- add error handling */
  jmsg = json_object();

  switch (msg->msg_type) 
    {
    case TPQ_REQUEST:
      jmsg_type = json_string("TPQRequest");
      json_object_set_new(jmsg, "msg_type", jmsg_type);
      json_object_set_new(jmsg, "msg_body", tr_msg_encode_tpqreq(msg->tpq_req));
      break;

    case TPQ_RESPONSE:
      jmsg_type = json_string("TPQResponse");
      json_object_set_new(jmsg, "msg_type", jmsg_type);
      json_object_set_new(jmsg, "msg_body", tr_msg_encode_tpqresp(msg->tpq_resp));
      break;

    case TIDR_REQUEST:
      jmsg_type = json_string("TIDRequest");
      json_object_set_new(jmsg, "msg_type", jmsg_type);
      json_object_set_new(jmsg, "msg_body", tr_msg_encode_tidrreq(msg->tidr_req));
      break;

    case TIDR_RESPONSE:
      jmsg_type = json_string("TIDResponse");
      json_object_set_new(jmsg, "msg_type", jmsg_type);
      json_object_set_new(jmsg, "msg_body", tr_msg_encode_tidrresp(msg->tidr_resp));
      break;

      /* TBD -- Add TR message types */

    default:
      json_decref(jmsg);
      return NULL;
    }
  
  return(json_dumps(jmsg, 0));
}

TR_MSG *tr_msg_decode(char *jmsg)
{
  TR_MSG *msg;

  if (!(msg = malloc(sizeof(TR_MSG *)))) {
    fprintf (stderr, "tr_msg_decode(): Error allocating TR_MSG structure.\n");
    return NULL;
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


