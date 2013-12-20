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

#include <stdio.h>
#include <stdlib.h>

#include <trust_router/tid.h>

TR_EXPORT TID_RC tid_resp_get_result(TID_RESP *resp)
{
  return(resp->result);
}

void tid_resp_set_result(TID_RESP *resp, TID_RC result)
{
  resp->result = result;
}

TR_EXPORT TR_NAME *tid_resp_get_err_msg(TID_RESP *resp)
{
  return(resp->err_msg);
}

void tid_resp_set_err_msg(TID_RESP *resp, TR_NAME *err_msg)
{
  resp->err_msg = err_msg;
}

TR_EXPORT TR_NAME *tid_resp_get_rp_realm(TID_RESP *resp)
{
  return(resp->rp_realm);
}

void tid_resp_set_rp_realm(TID_RESP *resp, TR_NAME *rp_realm)
{
  resp->rp_realm = rp_realm;
}

TR_EXPORT TR_NAME *tid_resp_get_realm(TID_RESP *resp)
{
  return(resp->realm);
}

void tid_resp_set_realm(TID_RESP *resp, TR_NAME *realm)
{
  resp->realm = realm;
}

TR_EXPORT TR_NAME *tid_resp_get_comm(TID_RESP *resp)
{
  return(resp->comm);
}

void tid_resp_set_comm(TID_RESP *resp, TR_NAME *comm)
{
  resp->comm = comm;
}

TR_EXPORT TR_NAME *tid_resp_get_orig_coi(TID_RESP *resp)
{
  return(resp->orig_coi);
}

void tid_resp_set_orig_coi(TID_RESP *resp, TR_NAME *orig_coi)
{
  resp->orig_coi = orig_coi;
}

TR_EXPORT TID_SRVR_BLK *tid_resp_get_servers(TID_RESP *resp)
{
  return(resp->servers);
}

void tid_resp_set_servers(TID_RESP *resp, TID_SRVR_BLK *servers)
{
  resp->servers = servers;
}
