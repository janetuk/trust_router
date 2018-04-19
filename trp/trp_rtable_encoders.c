/*
 * Copyright (c) 2016-2018, JANET(UK)
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

#include <stdlib.h>

#include <talloc.h>
#include <jansson.h>

#include <tr_name_internal.h>
#include <trp_route.h>
#include <trp_internal.h>
#include <trp_rtable.h>
#include <trust_router/trp.h>


static int sort_tr_names_cmp(const void *a, const void *b)
{
  TR_NAME **n1=(TR_NAME **)a;
  TR_NAME **n2=(TR_NAME **)b;
  return tr_name_cmp(*n1, *n2);
}

static void sort_tr_names(TR_NAME **names, size_t n_names)
{
  qsort(names, n_names, sizeof(TR_NAME *), sort_tr_names_cmp);
}

char *trp_rtable_to_str(TALLOC_CTX *mem_ctx, TRP_RTABLE *rtbl, const char *sep, const char *lineterm)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_NAME **comms=NULL;
  size_t n_comms=0;
  TR_NAME **realms=NULL;
  size_t n_realms=0;
  TRP_ROUTE **entries=NULL;
  size_t n_entries=0;
  char **tbl_strings=NULL;
  size_t ii_tbl=0; /* counts tbl_strings */
  size_t tbl_size=0;
  size_t len=0;
  size_t ii=0, jj=0, kk=0;
  char *p=NULL;
  char *result=NULL;

  if (lineterm==NULL)
    lineterm="\n";

  tbl_size=trp_rtable_size(rtbl);
  if (tbl_size==0) {
    result=talloc_strdup(mem_ctx, lineterm);
    goto cleanup;
  }

  tbl_strings=talloc_array(tmp_ctx, char *, tbl_size);
  if (tbl_strings==NULL) {
    result=talloc_strdup(mem_ctx, "error");
    goto cleanup;
  }

  comms=trp_rtable_get_comms(rtbl, &n_comms);
  talloc_steal(tmp_ctx, comms);
  sort_tr_names(comms, n_comms);
  ii_tbl=0;
  len=0;
  for (ii=0; ii<n_comms; ii++) {
    realms=trp_rtable_get_comm_realms(rtbl, comms[ii], &n_realms);
    talloc_steal(tmp_ctx, realms);
    sort_tr_names(realms, n_realms);
    for (jj=0; jj<n_realms; jj++) {
      entries=trp_rtable_get_realm_entries(rtbl, comms[ii], realms[jj], &n_entries);
      talloc_steal(tmp_ctx, entries);
      for (kk=0; kk<n_entries; kk++) {
        tbl_strings[ii_tbl]=trp_route_to_str(tmp_ctx, entries[kk], sep);
        len+=strlen(tbl_strings[ii_tbl]);
        ii_tbl++;
      }
      talloc_free(entries);
    }
    talloc_free(realms);
  }
  talloc_free(comms);

  /* now combine all the strings */
  len += tbl_size*strlen(lineterm); /* space for line terminations*/
  len += 1; /* nul terminator */
  result=(char *)talloc_size(tmp_ctx, len);
  for (p=result,ii=0; ii < tbl_size; ii++) {
    p+=sprintf(p, "%s%s", tbl_strings[ii], lineterm);
  }
  talloc_steal(mem_ctx, result);

cleanup:
  talloc_free(tmp_ctx);
  return result;
}


json_t *trp_rtable_to_json(TRP_RTABLE *rtbl)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  json_t *rtable_json = NULL;
  json_t *route_json = NULL;
  TRP_ROUTE **routes = NULL;
  size_t n_routes = 0;
  json_t *retval = NULL;

  /* Get the JSON array to return */
  rtable_json = json_array();
  if (rtable_json == NULL)
    goto cleanup;

  /* Get the array of routes */
  routes = trp_rtable_get_entries(tmp_ctx, rtbl, &n_routes);
  if (routes == NULL)
    goto cleanup;

  /* Gather JSON for each route */
  while (n_routes > 0) {
    route_json = trp_route_to_json(routes[--n_routes]);
    if (route_json == NULL)
      goto cleanup;
    json_array_append_new(rtable_json, route_json);
  }

  /* Success - set the return value and increment the reference count */
  retval = rtable_json;
  json_incref(retval);

cleanup:
  if (rtable_json)
    json_decref(rtable_json);
  talloc_free(tmp_ctx);
  return retval;
}
