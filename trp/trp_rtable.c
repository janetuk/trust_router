/*
 * Copyright (c) 2016, JANET(UK)
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

#include <glib.h>
#include <talloc.h>
#include <time.h>

#include <tr_name_internal.h>
#include <trp_route.h>
#include <trp_internal.h>
#include <trp_rtable.h>
#include <tr_debug.h>
#include <trust_router/trp.h>
#include <trust_router/tid.h>


/* result must be freed with g_free */
static gchar *tr_name_to_g_str(const TR_NAME *n)
{
  gchar *s=g_ascii_strdown(n->buf, n->len);
  if (s==NULL)
    tr_debug("tr_name_to_g_str: allocation failure.");
  return s;
}

/* hash function for TR_NAME keys */
static guint trp_tr_name_hash(gconstpointer key)
{
  const TR_NAME *name=(TR_NAME *)key;
  gchar *s=tr_name_to_g_str(name);
  guint hash=g_str_hash(s);
  g_free(s);
  return hash;
}

/* hash equality function for TR_NAME keys */
static gboolean trp_tr_name_equal(gconstpointer key1, gconstpointer key2)
{
  const TR_NAME *n1=(TR_NAME *)key1;
  const TR_NAME *n2=(TR_NAME *)key2;
  gchar *s1=tr_name_to_g_str(n1);
  gchar *s2=tr_name_to_g_str(n2);
  gboolean equal=g_str_equal(s1, s2);
  g_free(s1);
  g_free(s2);
  return equal;
}

/* free a value to the top level rtable (a hash of all entries in the comm) */
static void trp_rtable_destroy_table(gpointer data)
{
  g_hash_table_destroy(data);
}

static void trp_rtable_destroy_rentry(gpointer data)
{
  trp_route_free(data);
}

static void trp_rtable_destroy_tr_name(gpointer data)
{
  tr_free_name(data);
}

TRP_RTABLE *trp_rtable_new(void)
{
  GHashTable *new=g_hash_table_new_full(trp_tr_name_hash,
                                        trp_tr_name_equal,
                                        trp_rtable_destroy_tr_name,
                                        trp_rtable_destroy_table);
  return new;
}

void trp_rtable_free(TRP_RTABLE *rtbl)
{
  g_hash_table_destroy(rtbl);
}

static GHashTable *trp_rtbl_get_or_add_table(GHashTable *tbl, TR_NAME *key, GDestroyNotify destroy)
{
  GHashTable *val_tbl=NULL;

  val_tbl=g_hash_table_lookup(tbl, key);
  if (val_tbl==NULL) {
    val_tbl=g_hash_table_new_full(trp_tr_name_hash,
                                  trp_tr_name_equal,
                                  trp_rtable_destroy_tr_name,
                                  destroy);
    g_hash_table_insert(tbl, tr_dup_name(key), val_tbl);
  }
  return val_tbl;
}

void trp_rtable_add(TRP_RTABLE *rtbl, TRP_ROUTE *entry)
{
  GHashTable *comm_tbl=NULL;
  GHashTable *realm_tbl=NULL;

  comm_tbl=trp_rtbl_get_or_add_table(rtbl, entry->comm, trp_rtable_destroy_table);
  realm_tbl=trp_rtbl_get_or_add_table(comm_tbl, entry->realm, trp_rtable_destroy_rentry);
  g_hash_table_insert(realm_tbl, tr_dup_name(entry->peer), entry); /* destroys and replaces a duplicate */
  /* the route entry should not belong to any context, we will manage it ourselves */
  talloc_steal(NULL, entry);
}

/* note: the entry pointer passed in is invalid after calling this because the entry is freed */
void trp_rtable_remove(TRP_RTABLE *rtbl, TRP_ROUTE *entry)
{
  GHashTable *comm_tbl=NULL;
  GHashTable *realm_tbl=NULL;

  comm_tbl=g_hash_table_lookup(rtbl, entry->comm);
  if (comm_tbl==NULL)
    return;

  realm_tbl=g_hash_table_lookup(comm_tbl, entry->realm);
  if (realm_tbl==NULL)
    return;

  /* remove the element */
  g_hash_table_remove(realm_tbl, entry->peer);
  /* if that was the last entry in the realm, remove the realm table */
  if (g_hash_table_size(realm_tbl)==0)
    g_hash_table_remove(comm_tbl, entry->realm);
  /* if that was the last realm in the comm, remove the comm table */
  if (g_hash_table_size(comm_tbl)==0)
    g_hash_table_remove(rtbl, entry->comm);
}

void trp_rtable_clear(TRP_RTABLE *rtbl)
{
  g_hash_table_remove_all(rtbl); /* destructors should do all the cleanup */
}

/* gets the actual hash table, for internal use only */
static GHashTable *trp_rtable_get_comm_table(TRP_RTABLE *rtbl, TR_NAME *comm)
{
  return g_hash_table_lookup(rtbl, comm);
}

/* gets the actual hash table, for internal use only */
static GHashTable *trp_rtable_get_realm_table(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm)
{
  GHashTable *comm_tbl=trp_rtable_get_comm_table(rtbl, comm);
  if (comm_tbl==NULL)
    return NULL;
  else
    return g_hash_table_lookup(comm_tbl, realm);
}

struct table_size_cookie {
  TRP_RTABLE *rtbl;
  size_t size;
};
static void trp_rtable_size_helper(gpointer key, gpointer value, gpointer user_data)
{
  struct table_size_cookie *data=(struct table_size_cookie *)user_data;
  data->size += trp_rtable_comm_size(data->rtbl, (TR_NAME *)key);
};
size_t trp_rtable_size(TRP_RTABLE *rtbl)
{
  struct table_size_cookie data={rtbl, 0};
  g_hash_table_foreach(rtbl, trp_rtable_size_helper, &data);
  return data.size;
}

struct table_comm_size_cookie {
  TR_NAME *comm;
  TRP_RTABLE *rtbl;
  size_t size;
};
static void table_comm_size_helper(gpointer key, gpointer value, gpointer user_data)
{
  struct table_comm_size_cookie *data=(struct table_comm_size_cookie *)user_data;
  data->size += trp_rtable_realm_size(data->rtbl, data->comm, (TR_NAME *)key);
}
size_t trp_rtable_comm_size(TRP_RTABLE *rtbl, TR_NAME *comm)
{
  struct table_comm_size_cookie data={comm, rtbl, 0};
  GHashTable *comm_tbl=trp_rtable_get_comm_table(rtbl, comm);
  if (comm_tbl==NULL)
    return 0;;
  g_hash_table_foreach(comm_tbl, table_comm_size_helper, &data);
  return data.size;
}

size_t trp_rtable_realm_size(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm)
{
  GHashTable *realm_tbl=trp_rtable_get_realm_table(rtbl, comm, realm);
  if (realm_tbl==NULL)
    return 0;
  else
    return g_hash_table_size(g_hash_table_lookup(
                               g_hash_table_lookup(rtbl, comm),
                               realm));
}

/* Returns an array of pointers to TRP_ROUTE, length of array in n_out.
 * Caller must free the array (in the mem_ctx context), but must
 * not free its contents. */
TRP_ROUTE **trp_rtable_get_entries(TALLOC_CTX *mem_ctx, TRP_RTABLE *rtbl, size_t *n_out)
{
  TRP_ROUTE **ret=NULL;
  TR_NAME **comm=NULL;
  size_t n_comm=0;
  TRP_ROUTE **comm_entries=NULL;
  size_t n_entries=0;
  size_t ii_ret=0;

  *n_out=trp_rtable_size(rtbl);
  if (*n_out==0)
    return NULL;

  ret=talloc_array(mem_ctx, TRP_ROUTE *, *n_out);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_entries: unable to allocate return array.");
    *n_out=0;
    return NULL;
  }

  ii_ret=0; /* counts output entries */
  comm=trp_rtable_get_comms(rtbl, &n_comm);
  while(n_comm--) {
    comm_entries=trp_rtable_get_comm_entries(rtbl, comm[n_comm], &n_entries);
    while (n_entries--)
      ret[ii_ret++]=comm_entries[n_entries];
    talloc_free(comm_entries);
  }
  talloc_free(comm);

  if (ii_ret!=*n_out) {
    tr_crit("trp_rtable_get_entries: found incorrect number of entries.");
    talloc_free(ret);
    *n_out=0;
    return NULL;
  }
  return ret;
}

/* Returns an array of pointers to TR_NAME, length of array in n_out.
 * Caller must free the array (in the talloc NULL context). */
TR_NAME **trp_rtable_get_comms(TRP_RTABLE *rtbl, size_t *n_out)
{
  size_t len=g_hash_table_size(rtbl); /* known comms are keys in top level hash table */
  size_t ii=0;
  GList *comms=NULL;;
  GList *p=NULL;
  TR_NAME **ret=NULL;

  if (len==0) {
    *n_out=0;
    return NULL;
  }
    
  ret=talloc_array(NULL, TR_NAME *, len);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_comms: unable to allocate return array.");
    *n_out=0;
    return NULL;
  }
  comms=g_hash_table_get_keys(rtbl);
  for (ii=0,p=comms; p!=NULL; ii++,p=g_list_next(p))
    ret[ii]=(TR_NAME *)p->data;

  g_list_free(comms);

  *n_out=len;
  return ret;
}

/* Returns an array of pointers to TR_NAME, length of array in n_out.
 * Caller must free the array (in the talloc NULL context). */
TR_NAME **trp_rtable_get_comm_realms(TRP_RTABLE *rtbl, TR_NAME *comm, size_t *n_out)
{
  size_t ii=0;
  TRP_RTABLE *comm_tbl=g_hash_table_lookup(rtbl, comm);;
  GList *entries=NULL;
  GList *p=NULL;
  TR_NAME **ret=NULL;

  if (comm_tbl==NULL) {
    *n_out=0;
    return NULL;
  }
  *n_out=g_hash_table_size(comm_tbl); /* set output length */
  ret=talloc_array(NULL, TR_NAME *, *n_out);
  entries=g_hash_table_get_keys(comm_tbl);
  for (ii=0,p=entries; p!=NULL; ii++,p=g_list_next(p))
    ret[ii]=(TR_NAME *)p->data;

  g_list_free(entries);
  return ret;
}

/* Get all entries in an comm. Returns an array of pointers in NULL talloc context.
 * Caller must free this list with talloc_free, but must not free the entries in the
 * list.. */
TRP_ROUTE **trp_rtable_get_comm_entries(TRP_RTABLE *rtbl, TR_NAME *comm, size_t *n_out)
{
  size_t ii=0, jj=0;
  TR_NAME **realm=NULL;
  size_t n_realms=0;
  TRP_ROUTE **realm_entries=NULL;
  size_t n_entries=0;
  TRP_ROUTE **ret=NULL;
  size_t ii_ret=0;

  *n_out=trp_rtable_comm_size(rtbl, comm);
  if (*n_out==0)
    return NULL;

  ret=talloc_array(NULL, TRP_ROUTE *, *n_out);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_comm_entries: could not allocate return array.");
    *n_out=0;
    return NULL;
  }
  
  ii_ret=0; /* counts entries in the output array */
  realm=trp_rtable_get_comm_realms(rtbl, comm, &n_realms);
  for (ii=0; ii<n_realms; ii++) {
    realm_entries=trp_rtable_get_realm_entries(rtbl, comm, realm[ii], &n_entries);
    for (jj=0; jj<n_entries; jj++)
      ret[ii_ret++]=realm_entries[jj];
    talloc_free(realm_entries);
  }
  talloc_free(realm);

  if (ii_ret!=*n_out) {
    tr_crit("trp_rtable_get_comm_entries: found incorrect number of entries.");
    talloc_free(ret);
    *n_out=0;
    return NULL;
  }

  return ret;
}

/* Get all entries in an comm/realm. Returns an array of pointers in NULL talloc context.
 * Caller must free this list with talloc_free, but must not free the entries in the
 * list.
 *
 * If *n_out is 0, then no memory is allocated and NULL is returned. */
TRP_ROUTE **trp_rtable_get_realm_entries(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, size_t *n_out)
{
  size_t ii=0;
  TRP_ROUTE **ret=NULL;
  TR_NAME **peer=NULL;

  tr_debug("trp_rtable_get_realm_entries: entered.");
  peer=trp_rtable_get_comm_realm_peers(rtbl, comm, realm, n_out);
  if ((peer == NULL) || (*n_out == 0)) {
    *n_out = 0; /* May be redundant. That's ok, compilers are smart. */
    goto cleanup;
  }

  ret=talloc_array(NULL, TRP_ROUTE *, *n_out);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_realm_entries: could not allocate return array.");
    n_out=0;
    goto cleanup;
  }
  for (ii=0; ii<*n_out; ii++)
    ret[ii]=trp_rtable_get_entry(rtbl, comm, realm, peer[ii]);

cleanup:
  if (peer)
    talloc_free(peer);
  return ret;
}

TR_NAME **trp_rtable_get_comm_realm_peers(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, size_t *n_out)
{
  TR_NAME **ret=NULL;
  GHashTable *realm_tbl=NULL;
  GList *keys=NULL;
  GList *p=NULL;
  size_t ii=0;

  *n_out=trp_rtable_realm_size(rtbl, comm, realm);
  if (*n_out==0)
    return NULL;
  realm_tbl=trp_rtable_get_realm_table(rtbl, comm, realm);
  ret=talloc_array(NULL, TR_NAME *, *n_out);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_comm_realm_peers: could not allocate return array.");
    *n_out=0;
    return NULL;
  }
  keys=g_hash_table_get_keys(realm_tbl);
  for (ii=0,p=keys; p!=NULL; ii++,p=g_list_next(p))
    ret[ii]=(TR_NAME *)p->data;
  g_list_free(keys);
  return ret;
}

/* Gets a single entry. Do not free it. */
TRP_ROUTE *trp_rtable_get_entry(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer)
{
  GHashTable *realm_tbl=NULL;

  realm_tbl=trp_rtable_get_realm_table(rtbl, comm, realm);
  if (realm_tbl==NULL)
    return NULL;

  return g_hash_table_lookup(realm_tbl, peer); /* does not copy or increment ref count */
}

TRP_ROUTE *trp_rtable_get_selected_entry(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm)
{
  size_t n=0;
  int ii=0;
  TRP_ROUTE **entry=trp_rtable_get_realm_entries(rtbl, comm, realm, &n);
  TRP_ROUTE *selected=NULL;

  if (n==0)
    return NULL;

  tr_debug("trp_rtable_get_selected_entry: looking through route table entries for realm %.*s.",
           realm->len, realm->buf);
  for(ii=0; ii<n; ii++) {
    if (trp_route_is_selected(entry[ii])) {
      selected=entry[ii];
      break;
    }
  }
  tr_debug("trp_rtable_get_selected_entry: ii=%d.", ii);

  talloc_free(entry);
  return selected;
}

void trp_rtable_clear_triggered(TRP_RTABLE *rtbl)
{
  size_t n_entries=0;
  TRP_ROUTE **entries= trp_rtable_get_entries(NULL, rtbl, &n_entries);
  size_t ii=0;

  if (entries!=NULL) {
    for (ii=0; ii<n_entries; ii++)
      trp_route_set_triggered(entries[ii], 0);
    talloc_free(entries);
  }
}
