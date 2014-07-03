/*
 * Copyright (c) 2012, 2014, JANET(UK)
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

#include <openssl/dh.h>
#include <trust_router/tr_dh.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <talloc.h>
#include <assert.h>


unsigned char tr_2048_dhprime[2048/8] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
  0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
  0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
  0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
  0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
  0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
  0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
  0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
  0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
  0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
  0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
  0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
  0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
  0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
  0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
  0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
  0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
  0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
  0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
  0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

DH *tr_create_dh_params(unsigned char *priv_key, 
			size_t keylen) {

  DH *dh = NULL;
  int dh_err = 0;

  if (NULL == (dh = DH_new()))
    return NULL;

  if ((NULL == (dh->g = BN_new())) ||
      (NULL == (dh->p = BN_new())) ||
      (NULL == (dh->q = BN_new()))) {
    DH_free(dh);
  }

  BN_set_word(dh->g, 2);
  dh->p = BN_bin2bn(tr_2048_dhprime, sizeof(tr_2048_dhprime), NULL);
  BN_rshift1(dh->q, dh->p);

  if ((priv_key) && (keylen > 0))
    dh->priv_key = BN_bin2bn(priv_key, keylen, NULL);

  DH_generate_key(dh);		/* generates the public key */

  DH_check(dh, &dh_err);
  if (0 != dh_err) {
    fprintf(stderr, "Warning: dh_check failed with %d", dh_err);
    if (dh_err & DH_CHECK_P_NOT_PRIME)
      fprintf(stderr, ": p value is not prime\n");
    else if (dh_err & DH_CHECK_P_NOT_SAFE_PRIME)
      fprintf(stderr, ": p value is not a safe prime\n");
    else if (dh_err & DH_UNABLE_TO_CHECK_GENERATOR)
      fprintf(stderr, ": unable to check the generator value\n");
    else if (dh_err & DH_NOT_SUITABLE_GENERATOR)
      fprintf (stderr, ": the g value is not a generator\n");
    else 
      fprintf(stderr, "\n");
  }
  
  return(dh);
}

DH *tr_create_matching_dh (unsigned char *priv_key, 
			   size_t keylen,
			   DH *in_dh) {
  DH *dh = NULL;
  int dh_err = 0;

  if (!in_dh)
    return NULL;

  if (NULL == (dh = DH_new())) {
    fprintf(stderr, "Unable to allocate new DH structure.\n");
    return NULL;
  }

  if ((NULL == (dh->g = BN_dup(in_dh->g))) ||
      (NULL == (dh->p = BN_dup(in_dh->p)))) {
    DH_free(dh);
    fprintf(stderr, "Invalid dh parameter values, can't be duped.\n");
    return NULL;
  }

  /* TBD -- share code with previous function */
  if ((priv_key) && (keylen > 0))
    dh->priv_key = BN_bin2bn(priv_key, keylen, NULL);

  DH_generate_key(dh);		/* generates the public key */
  DH_check(dh, &dh_err);
  if (0 != dh_err) {
    fprintf(stderr, "Warning: dh_check failed with %d", dh_err);
    if (dh_err & DH_CHECK_P_NOT_PRIME)
      fprintf(stderr, ": p value is not prime\n");
    else if (dh_err & DH_CHECK_P_NOT_SAFE_PRIME)
      fprintf(stderr, ": p value is not a safe prime\n");
    else if (dh_err & DH_UNABLE_TO_CHECK_GENERATOR)
      fprintf(stderr, ": unable to check the generator value\n");
    else if (dh_err & DH_NOT_SUITABLE_GENERATOR)
      fprintf (stderr, ": the g value is not a generator\n");
    else 
      fprintf(stderr, "\n");
  }
  
  return(dh);
}

void tr_destroy_dh_params(DH *dh) {

  if (dh) {
    DH_free(dh);
  }
}

int tr_compute_dh_key(unsigned char **pbuf, 
		      BIGNUM *pub_key, 
		      DH *priv_dh) {
  size_t buflen;
  unsigned char *buf = NULL;;
  int rc = 0;
  
  if ((!pbuf) || 
      (!pub_key) || 
      (!priv_dh)) {
    fprintf(stderr, "tr_compute_dh_key(): Invalid parameters.\n");
    return(-1);
  }
  *pbuf = NULL;
  buflen = DH_size(priv_dh);
  buf = malloc(buflen);
  if (buf == NULL) {
    fprintf(stderr, "out of memory\n");
    return -1;
  }

  
  rc = DH_compute_key(buf, pub_key, priv_dh);
  if (0 <= rc) {
    *pbuf = buf;
  }else {
    free(buf);
  }
  return rc;
}




int tr_dh_pub_hash(TID_REQ *request,
		   unsigned char **out_digest,
		   size_t *out_len)
{
  const BIGNUM *pub = request->tidc_dh->pub_key;
  unsigned char *bn_bytes = talloc_zero_size(request, BN_num_bytes(pub));
  unsigned char *digest = talloc_zero_size(request, SHA_DIGEST_LENGTH+1);
  assert(bn_bytes && digest);
				    BN_bn2bin(pub, bn_bytes);
				    SHA1(bn_bytes, BN_num_bytes(pub), digest);
				    *out_digest = digest;
				    *out_len = SHA_DIGEST_LENGTH;
				    return 0;
}
