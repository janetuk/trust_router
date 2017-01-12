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

#ifndef TR_DH_H
#define TR_DH_H

#include <openssl/dh.h>
#include <openssl/bn.h>
#include <trust_router/tr_versioning.h>
#include <trust_router/tid.h>

TR_EXPORT DH *tr_dh_new(void);
TR_EXPORT void tr_dh_destroy(DH *dh); /* called destroy because free is already used */
TR_EXPORT DH *tr_create_dh_params(unsigned char *key, size_t len);
TR_EXPORT DH *tr_create_matching_dh(unsigned char *key, size_t len, DH *in_dh);
TR_EXPORT void tr_destroy_dh_params(DH *dh);
TR_EXPORT DH *tr_dh_dup(DH *in);
TR_EXPORT int tr_compute_dh_key(unsigned char **pbuf,  BIGNUM *pub_key, DH *priv_dh);

TR_EXPORT void tr_dh_free(unsigned char *dh_buf);
int TR_EXPORT tr_dh_pub_hash(TID_REQ *request,
			     unsigned char **out_digest,
			     size_t *out_llen);

TR_EXPORT void tr_bin_to_hex(const unsigned char * bin, size_t binlen,
                             char * hex_out, size_t hex_len);


#endif
