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
#include <tr_msg.h>
#include <tr_util.h>
#include <tr_name_internal.h>
#include <trust_router/tr_constraint.h>
#include <trust_router/tr_dh.h>
#include <tr_debug.h>
#include <tr_inet_util.h>

#define MAX_MSG_TYPES 10
static TR_MSG_TYPE_HANDLER msg_type_handler_table[MAX_MSG_TYPES] = {{0}};

static TR_MSG_TYPE_HANDLER *get_msg_type_handler(TR_MSG_TYPE msg_type)
{
  /* In this implementation, the (msg_type-1)th entry in the table will
   * always be the handler for msg_type. Just check that it is not undefined */
  if (msg_type_handler_table[msg_type - 1].msg_type == msg_type)
    return &(msg_type_handler_table[msg_type - 1]);

  return NULL;
}

static TR_MSG_TYPE_HANDLER *get_msg_type_handler_by_label(const char *label)
{
  size_t ii;
  for (ii = 0; ii < MAX_MSG_TYPES; ii++) {
    if (0 == strcmp(label, msg_type_handler_table[ii].msg_type_label))
      return &(msg_type_handler_table[ii]);
  }
  return NULL;
}

TR_MSG_TYPE tr_msg_register_type(const char *msg_type_label,
                                 TR_MSG_DECODE_FUNC *decode,
                                 TR_MSG_ENCODE_FUNC *encode)
{
  size_t ii;
  TR_MSG_TYPE_HANDLER *handler;

  if ((!msg_type_label)
     || (!decode && !encode)) {
    return TR_MSG_TYPE_UNKNOWN;
  }

  /* Do we already have a handler for this type? */
  handler = get_msg_type_handler_by_label(msg_type_label);

  /* if not, add one if we have space */
  if (!handler) {
    for(ii = 0; ii < MAX_MSG_TYPES; ii++) {
      handler = &(msg_type_handler_table[ii]);

      if (TR_MSG_TYPE_UNKNOWN == handler->msg_type)
        break;
    }

    /* did we find a slot? */
    if (ii >= MAX_MSG_TYPES)
      return -1; /* failed */

    handler->msg_type = ii + 1; /* redundant with the index in this implementation */

    /* make our own copy of the name */
    strncpy(handler->msg_type_label, msg_type_label, MSG_TYPE_LABEL_LEN);
    handler->msg_type_label[MSG_TYPE_LABEL_LEN] = '\0'; /* ensure null termination */

  }

  /* fill in or replace the encode/decode functions */
  handler->decode = decode;
  handler->encode = encode;

  return handler->msg_type;
}


int tr_msg_set_rep(TR_MSG *msg, void *msg_rep)
{
  if (!msg) {
    tr_err("tr_msg_set_rep: msg is null");
    return 0;
  }

  msg->msg_rep = msg_rep;
  return 1;
}

void *tr_msg_get_rep(TR_MSG *msg)
{
  if (msg)
    return msg->msg_rep;
  return NULL;
}

TR_MSG_TYPE tr_msg_get_msg_type(TR_MSG *msg)
{
  return msg->msg_type;
}

void tr_msg_set_msg_type(TR_MSG *msg, TR_MSG_TYPE type)
{
  msg->msg_type = type;
}

char *tr_msg_encode(TALLOC_CTX *mem_ctx, TR_MSG *msg)
{
  TR_MSG_TYPE_HANDLER *handler = NULL;
  json_t *jmsg=NULL;
  json_t *jmsg_type=NULL;
  char *encoded_tmp=NULL;
  char *encoded=NULL;

  handler = get_msg_type_handler(tr_msg_get_msg_type(msg));
  if (!handler || !(handler->encode))
    return NULL; /* no encoder for this type */

  /* TBD -- add error handling */
  jmsg = json_object();
  jmsg_type  = json_string(handler->msg_type_label);
  json_object_set_new(jmsg, "msg_type", jmsg_type);
  json_object_set_new(jmsg, "msg_body", handler->encode(msg->msg_rep));

  /* We should perhaps use json_set_alloc_funcs to automatically use talloc, but for
   * now, we'll encode to a malloc'ed buffer, then copy that to a talloc'ed buffer. */
  encoded_tmp=json_dumps(jmsg, 0);                // malloc'ed version
  json_decref(jmsg);                              // free the JSON structure
  encoded = talloc_strdup(mem_ctx, encoded_tmp);  // get the talloc'ed version
  free(encoded_tmp);                              // free the malloc'ed version

  tr_debug("tr_msg_encode: outgoing msg=%s", encoded);
  return encoded;
}

TR_MSG *tr_msg_decode(TALLOC_CTX *mem_ctx, const char *jbuf, size_t buflen)
{
  TR_MSG_TYPE_HANDLER *handler=NULL;
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

  if (!(msg = talloc_zero(mem_ctx, TR_MSG))) {
    tr_debug("tr_msg_decode(): Error allocating TR_MSG structure.");
    json_decref(jmsg);
    return NULL;
  }

  if ((NULL == (jtype = json_object_get(jmsg, "msg_type"))) ||
      (NULL == (jbody = json_object_get(jmsg, "msg_body")))) {
    tr_debug("tr_msg_decode(): Error parsing message header.");
    json_decref(jmsg);
    tr_msg_free_decoded(msg);
    return NULL;
  }

  mtype = json_string_value(jtype);

  handler = get_msg_type_handler_by_label(mtype);
  if (handler && (handler->decode)) {
    tr_msg_set_msg_type(msg, handler->msg_type);
    msg->msg_rep = handler->decode(msg, jbody);
  } else {
    tr_msg_set_msg_type(msg, TR_MSG_TYPE_UNKNOWN);
    msg->msg_rep = NULL;
  }

  json_decref(jmsg);

  return msg;
}

void tr_msg_free_encoded(char *jmsg)
{
  if (jmsg)
    talloc_free(jmsg);
}

void tr_msg_free_decoded(TR_MSG *msg)
{
  if (msg)
    talloc_free(msg);
}
