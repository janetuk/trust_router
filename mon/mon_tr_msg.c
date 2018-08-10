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

/* Global handle for message types */
static struct {
  TR_MSG_TYPE mon_request;
  TR_MSG_TYPE mon_response;
} mon_msg_type = {TR_MSG_TYPE_UNKNOWN, TR_MSG_TYPE_UNKNOWN};

/* Must call this before sending or receiving MON messages */
int mon_tr_msg_init(void)
{
  int result = 1; /* 1 is success */

  if (mon_msg_type.mon_request == TR_MSG_TYPE_UNKNOWN) {
    mon_msg_type.mon_request = tr_msg_register_type("mon_request",
                                                    mon_req_decode,
                                                    mon_req_encode);
    if (mon_msg_type.mon_request == TR_MSG_TYPE_UNKNOWN) {
      tr_err("mon_tr_msg_init: unable to register MON request message type");
      result = 0;
    }
  }

  if (mon_msg_type.mon_response == TR_MSG_TYPE_UNKNOWN) {
    mon_msg_type.mon_response = tr_msg_register_type("mon_response",
                                                     mon_resp_decode,
                                                     mon_resp_encode);
    if (mon_msg_type.mon_response == TR_MSG_TYPE_UNKNOWN) {
      tr_err("mon_tr_msg_init: unable to register MON response message type");
      result = 0;
    }
  }

  return result;
}

/**
 * Set the message payload to a MON request
 *
 * Sets the message type
 */
void mon_set_tr_msg_req(TR_MSG *msg, MON_REQ *req)
{
  tr_msg_set_msg_type(msg, mon_msg_type.mon_request);
  tr_msg_set_rep(msg, req);
}

/**
 * Get the MON request from a generic TR_MSG
 *
 * Returns null if the message is not a MON request
 */
MON_REQ *mon_get_tr_msg_req(TR_MSG *msg)
{
  if (tr_msg_get_msg_type(msg) == mon_msg_type.mon_request)
    return (MON_REQ *) tr_msg_get_rep(msg);
  return NULL;
}

/**
 * Set the message payload to a MON response
 *
 * Sets the message type
 */
void mon_set_tr_msg_resp(TR_MSG *msg, MON_RESP *resp)
{
  tr_msg_set_msg_type(msg, mon_msg_type.mon_response);
  tr_msg_set_rep(msg, resp);
}

/**
 * Get the MON response from a generic TR_MSG
 *
 * Returns null if the message is not a MON response
 */
MON_RESP *mon_get_tr_msg_resp(TR_MSG *msg)
{
  if (tr_msg_get_msg_type(msg) == mon_msg_type.mon_response)
    return (MON_RESP *) tr_msg_get_rep(msg);
  return NULL;
}
