/*
 * Copyright (c) 2012-2014, JANET(UK)
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

#ifndef TR_MSG_H
#define TR_MSG_H

#include <jansson.h>
#include <trust_router/tid.h>
#include <trust_router/trp.h>
#include <mon.h>

typedef struct tr_msg TR_MSG;

#define TR_MSG_TYPE_UNKNOWN 0
typedef unsigned int TR_MSG_TYPE;

/* Union of TR message types to hold message of any type. */
struct tr_msg {
  TR_MSG_TYPE msg_type;
  void *msg_rep;
};

typedef void *(TR_MSG_DECODE_FUNC)(TALLOC_CTX *, json_t *);
typedef json_t *(TR_MSG_ENCODE_FUNC)(void *);

#define MSG_TYPE_LABEL_LEN 30
typedef struct tr_msg_type_handler {
  TR_MSG_TYPE msg_type;
  char msg_type_label[MSG_TYPE_LABEL_LEN+1]; /* +1 to allow space for null term */
  TR_MSG_DECODE_FUNC *decode;
  TR_MSG_ENCODE_FUNC *encode;
} TR_MSG_TYPE_HANDLER;

TR_MSG_TYPE tr_msg_register_type(const char *msg_type_label,
                                 TR_MSG_DECODE_FUNC *decode,
                                 TR_MSG_ENCODE_FUNC *encode);

/* Accessors */
int tr_msg_set_rep(TR_MSG *msg, void *msg_rep);
void *tr_msg_get_rep(TR_MSG *msg);
TR_MSG_TYPE tr_msg_get_msg_type(TR_MSG *msg);
void tr_msg_set_msg_type(TR_MSG *msg, TR_MSG_TYPE type);

/* Encoders/Decoders */
char *tr_msg_encode(TALLOC_CTX *mem_ctx, TR_MSG *msg);
TR_MSG *tr_msg_decode(TALLOC_CTX *mem_ctx, const char *jmsg, size_t len);
void tr_msg_free_encoded(char *jmsg);
void tr_msg_free_decoded(TR_MSG *msg);

#endif
