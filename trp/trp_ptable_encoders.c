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

#include <talloc.h>
#include <trp_peer.h>
#include <trp_ptable.h>

/* this is horribly inefficient but should be ok for small peer tables */
char *trp_ptable_to_str(TALLOC_CTX *memctx, TRP_PTABLE *ptbl, const char *sep, const char *lineterm)
{
  TALLOC_CTX *tmpctx=talloc_new(NULL);
  TRP_PEER *peer=NULL;
  char *result=talloc_strdup(tmpctx, "");

  if (lineterm==NULL)
    lineterm="\n";

  /* this leaves intermediate result strings in the tmpctx context, we'll free these when
   * we're done */
  for (peer=ptbl->head; peer!=NULL; peer=peer->next)
    result=talloc_asprintf(tmpctx, "%s%s%s", result, lineterm, trp_peer_to_str(tmpctx, peer, sep));

  talloc_steal(memctx, result); /* hand result over to caller */
  talloc_free(tmpctx); /* free detritus */
  return result;
}

json_t *trp_ptable_to_json(TRP_PTABLE *ptbl)
{
  TRP_PTABLE_ITER *iter = trp_ptable_iter_new(NULL);
  json_t *ptbl_json = json_array();
  TRP_PEER *peer = NULL;

  for (trp_ptable_iter_first(iter, ptbl);
       peer != NULL;
       peer = trp_ptable_iter_next(iter)) {
    json_array_append_new(ptbl_json, trp_peer_to_json(peer));
  }
  trp_ptable_iter_free(iter);
  return ptbl_json;
}
