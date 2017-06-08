/*
 * Copyright (c) 2017, JANET(UK)
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
#include <assert.h>

#include <trp_internal.h>
#include <tid_internal.h>
#include <tr_filter.h>
#include <tr_config.h>

#define FILTER_PATH "./test-filters/"

/**
 * Load a JSON file containing filters and return the filters from the first rp_client.
 *
 * @param fname File to read
 * @param filt_out Will point to the loaded filter on success
 * @return Return value from tr_cfg_parse_one_config_file()
 */
int load_filter(const char *fname, TR_FILTER **filt_out)
{
  TR_CFG *cfg=tr_cfg_new(NULL);
  TR_CFG_RC rc=TR_CFG_ERROR;

  assert(fname);
  assert(filt_out);

  rc=tr_cfg_parse_one_config_file(cfg, fname);
  if (rc!=TR_CFG_SUCCESS)
    goto cleanup;

  /* Steal the filter from the first rp_client */
  assert(cfg);
  assert(cfg->rp_clients);
  assert(cfg->rp_clients->filter);
  *filt_out=cfg->rp_clients->filter;
  cfg->rp_clients->filter=NULL; /* can't use the _set_filter() because that will free the filter */
  talloc_steal(NULL, *filt_out);

cleanup:
  tr_cfg_free(cfg);
  return rc;
}

/**
 * Test that filters load / fail to load as expected.
 *
 * @return 1 if all tests pass
 */
int test_load_filter(void)
{
  TR_FILTER *filt=NULL;

  assert(TR_CFG_SUCCESS==load_filter(FILTER_PATH "valid-filt.json", &filt));
  assert(TR_CFG_NOPARSE==load_filter(FILTER_PATH "invalid-filt-repeated-key.json", &filt));
  assert(TR_CFG_ERROR==load_filter(FILTER_PATH "invalid-filt-unknown-field.json", &filt));
  return 1;
}

int test_trp_inforec_filter(TRP_INFOREC_TYPE type)
{
  TRP_INFOREC *inforec=trp_inforec_new(NULL, type);
  TR_FILTER *filt=tr_filter_new(NULL);

  assert(inforec);
  assert(filt);


  return 1;
}


int test_trp_filter(void)
{
  assert(test_trp_inforec_filter(TRP_INFOREC_TYPE_ROUTE));
  assert(test_trp_inforec_filter(TRP_INFOREC_TYPE_COMMUNITY));
  return 1;
}



int main(void)
{
  assert(test_load_filter());
  printf("Success\n");
  return 0;
}