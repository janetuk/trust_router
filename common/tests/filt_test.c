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
#include <string.h>
#include <jansson.h>
#if JANSSON_VERSION_HEX < 0x020500
#include "../jansson_iterators.h"
#endif
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
int load_filter(char *fname, TR_FILTER_SET **filts_out)
{
  TR_CFG_MGR *cfg_mgr=tr_cfg_mgr_new(NULL);
  TR_CFG_RC rc=TR_CFG_ERROR;

  assert(cfg_mgr);
  assert(fname);
  assert(filts_out);

  rc=tr_parse_config(cfg_mgr, 1, &fname);
  if (rc!=TR_CFG_SUCCESS)
    goto cleanup;

  /* Steal the filter from the first rp_client */
  assert(cfg_mgr->new);
  assert(cfg_mgr->new->rp_clients);
  assert(cfg_mgr->new->rp_clients->filters);
  *filts_out=cfg_mgr->new->rp_clients->filters;
  cfg_mgr->new->rp_clients->filters=NULL; /* can't use the _set_filter() because that will free the filter */
  talloc_steal(NULL, *filts_out);

cleanup:
  tr_cfg_mgr_free(cfg_mgr);
  return rc;
}

/**
 * Test that filters load / fail to load as expected.
 *
 * @return 1 if all tests pass
 */
int test_load_filter(void)
{
  TR_FILTER_SET *filts=NULL;

  assert(TR_CFG_SUCCESS==load_filter(FILTER_PATH "valid-filt.json", &filts));
  if (filts) tr_filter_set_free(filts);
  filts=NULL;
  assert(TR_CFG_NOPARSE==load_filter(FILTER_PATH "invalid-filt-repeated-key.json", &filts));
  if (filts) tr_filter_set_free(filts);
  filts=NULL;
  assert(TR_CFG_NOPARSE==load_filter(FILTER_PATH "invalid-filt-unknown-field.json", &filts));
  if (filts) tr_filter_set_free(filts);
  filts=NULL;
  return 1;
}

/**
 * Read the first inforec from the TR_MSG encoded in JSON file named fname.
 *
 * @param fname Filename with path for TR_MSG JSON
 * @return Pointer to the decoded inforec, or NULL on failure
 */
TRP_INFOREC *load_inforec(const char *fname)
{
  TR_MSG *msg=NULL;
  TRP_UPD *upd=NULL;
  TRP_INFOREC *inforec=NULL;
  json_t *decoded=json_load_file(fname, JSON_REJECT_DUPLICATES|JSON_DISABLE_EOF_CHECK, NULL);
  char *encoded=json_dumps(decoded, 0); /* silly way to read the file without mucking around */

  assert(decoded);
  json_decref(decoded);

  assert(encoded);
  assert(msg= tr_msg_decode(NULL, encoded, strlen(encoded)));
  assert(upd=tr_msg_get_trp_upd(msg));
  assert(inforec=trp_upd_get_inforec(upd));
  /* now remove the inforec from the update context */
  talloc_steal(NULL, inforec);
  tr_msg_free_decoded(msg);
  tr_msg_free_encoded(encoded);
  return inforec;
}

/* make this bigger than your message file */
#define MAX_FILE_SIZE 20000
TID_REQ *load_tid_req(const char *fname)
{
  TID_REQ *out=NULL;
  TR_MSG *msg=NULL;
  FILE *f=NULL;
  char *msgbuf=NULL;
  size_t msglen=0;

  msgbuf=malloc(MAX_FILE_SIZE);
  assert(msgbuf);
  f=fopen(fname, "r");
  assert(f);
  msglen=fread(msgbuf, 1, MAX_FILE_SIZE, f);
  assert(msglen);
  assert(feof(f));
  msg= tr_msg_decode(NULL, msgbuf, msglen);
  free(msgbuf);
  msgbuf=NULL;

  assert(msg);
  assert(tr_msg_get_msg_type(msg)==TID_REQUEST);

  /* take the tid req out of the msg */
  out=tr_msg_get_req(msg);
  tr_msg_set_req(msg, NULL);
  assert(out);

  tr_msg_free_decoded(msg);
  return out;
}

/**
 * Read a set of filters from a config JSON in filt_fname and test against the tid_req or inforec in target_fname.
 * If expect==1, succeed if the target is accepted by the filter, otherwise succeed if it is rejected.
 * Takes filters from the first rp_realm defined in the filter file and the first inforec or tid req from
 * the target file.
 *
 * @param filt_fname Name of JSON file containing filters
 * @param ftype Which type of filter to test
 * @param target_fname  Name of JSON file containing inforec
 * @param expected_match 1 if we expect a match, 0 otherwise
 * @param expected_action Expected action if the filter matches
 * @return 1 if expected result is obtained, 0 or does not return otherwise
 */
int test_one_filter(char *filt_fname,
                    TR_FILTER_TYPE ftype,
                    const char *target_fname,
                    int expected_match,
                    TR_FILTER_ACTION expected_action)
{
  TR_FILTER_TARGET *target=NULL;
  TR_FILTER_SET *filts=NULL;
  TR_FILTER_ACTION action=TR_FILTER_ACTION_UNKNOWN;

  /* load filter for first test */
  assert(TR_CFG_SUCCESS==load_filter(filt_fname, &filts));

  /* load the target req or inforec */
  switch(ftype) {
    case TR_FILTER_TYPE_TID_INBOUND:
      target=tr_filter_target_tid_req(NULL, load_tid_req(target_fname));
      break;

    case TR_FILTER_TYPE_TRP_INBOUND:
    case TR_FILTER_TYPE_TRP_OUTBOUND:
      /* TODO: read realm and community */
      target= tr_filter_target_trp_inforec(NULL, NULL, load_inforec(target_fname));
      break;

    default:
      printf("Unknown filter type.\n");
  }
  assert(target);

  assert(expected_match==tr_filter_apply(target, tr_filter_set_get(filts, ftype), NULL, &action));
  if (expected_match==TR_FILTER_MATCH)
    assert(action==expected_action);

  tr_filter_set_free(filts);
  switch(ftype) {
    case TR_FILTER_TYPE_TID_INBOUND:
      tid_req_free(target->tid_req);
      break;

    case TR_FILTER_TYPE_TRP_INBOUND:
    case TR_FILTER_TYPE_TRP_OUTBOUND:
      trp_inforec_free(target->trp_inforec);
      if (target->trp_upd!=NULL)
        trp_upd_free(target->trp_upd);
      break;

    default:
      printf("Unknown filter type.\n");
  }
  tr_filter_target_free(target);
  return 1;
}

int test_filter(void)
{
  json_t *test_list=json_load_file(FILTER_PATH "filter-tests.json", JSON_DISABLE_EOF_CHECK, NULL);
  json_t *this;
  size_t ii;
  char *filt_file, *target_file;
  TR_FILTER_TYPE ftype;
  int expect_match;
  TR_FILTER_ACTION action;

  json_array_foreach(test_list, ii, this) {
    printf("Running filter test case: %s\n", json_string_value(json_object_get(this, "test label")));
    fflush(stdout);

    filt_file=talloc_strdup(NULL, json_string_value(json_object_get(this, "filter file")));
    ftype=tr_filter_type_from_string(json_string_value(json_object_get(this, "filter type")));
    target_file=talloc_strdup(NULL, json_string_value(json_object_get(this, "target file")));
    if (0==strcmp("yes", json_string_value(json_object_get(this, "expect match"))))
      expect_match=TR_FILTER_MATCH;
    else
      expect_match=TR_FILTER_NO_MATCH;

    if (0==strcmp("accept", json_string_value(json_object_get(this, "action"))))
      action=TR_FILTER_ACTION_ACCEPT;
    else
      action=TR_FILTER_ACTION_REJECT;

    assert(test_one_filter(filt_file, ftype, target_file, expect_match, action));

    talloc_free(filt_file);
    talloc_free(target_file);
  }

  return 1;
}



int main(void)
{
  assert(test_load_filter());
  assert(test_filter());
  printf("Success\n");
  return 0;
}
