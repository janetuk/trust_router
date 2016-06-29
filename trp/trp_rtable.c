#include <glib.h>
#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <trp_rtable.h>
#include <tr_debug.h>

/* Note: be careful mixing talloc with glib. */

static int trp_rentry_destructor(void *obj)
{
  TRP_RENTRY *entry=talloc_get_type_abort(obj, TRP_RENTRY);
  if (entry->apc!=NULL)
    tr_free_name(entry->apc);
  if (entry->realm!=NULL)
    tr_free_name(entry->realm);
  if (entry->trust_router!=NULL)
    tr_free_name(entry->trust_router);
  if (entry->peer!=NULL)
    tr_free_name(entry->peer);
  if (entry->next_hop!=NULL)
    tr_free_name(entry->next_hop);
  return 0;
}

TRP_RENTRY *trp_rentry_new(TALLOC_CTX *mem_ctx)
{
  TRP_RENTRY *entry=talloc(mem_ctx, TRP_RENTRY);
  if (entry!=NULL) {
    entry->apc=NULL;
    entry->realm=NULL;
    entry->trust_router=NULL;
    entry->peer=NULL;
    entry->next_hop=NULL;
    entry->selected=0;
    entry->expiry=talloc(entry, struct timespec);
    if (entry->expiry==NULL) {
      talloc_free(entry);
      return NULL;
    }
    talloc_set_destructor((void *)entry, trp_rentry_destructor);
  }
  return entry;
}

void trp_rentry_free(TRP_RENTRY *entry)
{
  if (entry!=NULL)
    talloc_free(entry);
}

void trp_rentry_set_apc(TRP_RENTRY *entry, TR_NAME *apc)
{
  entry->apc=apc;
}

TR_NAME *trp_rentry_get_apc(TRP_RENTRY *entry)
{
  return entry->apc;
}

void trp_rentry_set_realm(TRP_RENTRY *entry, TR_NAME *realm)
{
  entry->realm=realm;
}

TR_NAME *trp_rentry_get_realm(TRP_RENTRY *entry)
{
  return entry->realm;
}

void trp_rentry_set_trust_router(TRP_RENTRY *entry, TR_NAME *tr)
{
  entry->trust_router=tr;
}

TR_NAME *trp_rentry_get_trust_router(TRP_RENTRY *entry)
{
  return entry->trust_router;
}

void trp_rentry_set_peer(TRP_RENTRY *entry, TR_NAME *peer)
{
  entry->peer=peer;
}

TR_NAME *trp_rentry_get_peer(TRP_RENTRY *entry)
{
  return entry->peer;
}

void trp_rentry_set_metric(TRP_RENTRY *entry, unsigned int metric)
{
  entry->metric=metric;
}

unsigned int trp_rentry_get_metric(TRP_RENTRY *entry)
{
  return entry->metric;
}

void trp_rentry_set_next_hop(TRP_RENTRY *entry, TR_NAME *next_hop)
{
  entry->next_hop=next_hop;
}

TR_NAME *trp_rentry_get_next_hop(TRP_RENTRY *entry)
{
  return entry->next_hop;
}

void trp_rentry_set_selected(TRP_RENTRY *entry, int sel)
{
  entry->selected=sel;
}

int trp_rentry_get_selected(TRP_RENTRY *entry)
{
  return entry->selected;
}

/* copies incoming value, does not assume responsibility for freeing */
void trp_rentry_set_expiry(TRP_RENTRY *entry, struct timespec *exp)
{
  entry->expiry->tv_sec=exp->tv_sec;
  entry->expiry->tv_nsec=exp->tv_nsec;
}

struct timespec *trp_rentry_get_expiry(TRP_RENTRY *entry)
{
  return entry->expiry;
}


/* result must be freed with g_free */
static gchar *tr_name_to_g_str(const TR_NAME *n)
{
  gchar *s=g_strndup(n->buf, n->len);
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

/* free a value to the top level rtable (a hash of all entries in the apc) */
static void trp_rtable_destroy_table(gpointer data)
{
  g_hash_table_destroy(data);
}

static void trp_rtable_destroy_rentry(gpointer data)
{
  trp_rentry_free(data);
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

void trp_rtable_add(TRP_RTABLE *rtbl, TRP_RENTRY *entry)
{
  GHashTable *apc_tbl=NULL;
  GHashTable *realm_tbl=NULL;

  apc_tbl=trp_rtbl_get_or_add_table(rtbl, entry->apc, trp_rtable_destroy_table);
  realm_tbl=trp_rtbl_get_or_add_table(apc_tbl, entry->realm, trp_rtable_destroy_rentry);
  g_hash_table_insert(realm_tbl, tr_dup_name(entry->peer), entry); /* destroys and replaces a duplicate */
}

/* note: the entry pointer passed in is invalid after calling this because the entry is freed */
void trp_rtable_remove(TRP_RTABLE *rtbl, TRP_RENTRY *entry)
{
  GHashTable *apc_tbl=NULL;
  GHashTable *realm_tbl=NULL;

  apc_tbl=g_hash_table_lookup(rtbl, entry->apc);
  if (apc_tbl==NULL)
    return;

  realm_tbl=g_hash_table_lookup(apc_tbl, entry->realm);
  if (realm_tbl==NULL)
    return;

  /* remove the element */
  g_hash_table_remove(realm_tbl, entry->peer);
  /* if that was the last entry in the realm, remove the realm table */
  if (g_hash_table_size(realm_tbl)==0)
    g_hash_table_remove(apc_tbl, entry->realm);
  /* if that was the last realm in the apc, remove the apc table */
  if (g_hash_table_size(apc_tbl)==0)
    g_hash_table_remove(rtbl, entry->apc);
}

/* gets the actual hash table, for internal use only */
static GHashTable *trp_rtable_get_apc_table(TRP_RTABLE *rtbl, TR_NAME *apc)
{
  return g_hash_table_lookup(rtbl, apc);
}

/* gets the actual hash table, for internal use only */
static GHashTable *trp_rtable_get_realm_table(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm)
{
  GHashTable *apc_tbl=trp_rtable_get_apc_table(rtbl, apc);
  if (apc_tbl==NULL)
    return NULL;
  else
    return g_hash_table_lookup(apc_tbl, realm);
}

struct table_size_cookie {
  TRP_RTABLE *rtbl;
  size_t size;
};
static void trp_rtable_size_helper(gpointer key, gpointer value, gpointer user_data)
{
  struct table_size_cookie *data=(struct table_size_cookie *)user_data;
  data->size += trp_rtable_apc_size(data->rtbl, (TR_NAME *)key);
};
size_t trp_rtable_size(TRP_RTABLE *rtbl)
{
  struct table_size_cookie data={rtbl, 0};
  g_hash_table_foreach(rtbl, trp_rtable_size_helper, &data);
  return data.size;
}

struct table_apc_size_cookie {
  TR_NAME *apc;
  TRP_RTABLE *rtbl;
  size_t size;
};
static void table_apc_size_helper(gpointer key, gpointer value, gpointer user_data)
{
  struct table_apc_size_cookie *data=(struct table_apc_size_cookie *)user_data;
  data->size += trp_rtable_realm_size(data->rtbl, data->apc, (TR_NAME *)key);
}
size_t trp_rtable_apc_size(TRP_RTABLE *rtbl, TR_NAME *apc)
{
  struct table_apc_size_cookie data={apc, rtbl, 0};
  GHashTable *apc_tbl=trp_rtable_get_apc_table(rtbl, apc);
  if (apc_tbl==NULL)
    return 0;;
  g_hash_table_foreach(apc_tbl, table_apc_size_helper, &data);
  return data.size;
}

size_t trp_rtable_realm_size(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm)
{
  GHashTable *realm_tbl=trp_rtable_get_realm_table(rtbl, apc, realm);
  if (realm_tbl==NULL)
    return 0;
  else
    return g_hash_table_size(g_hash_table_lookup(
                               g_hash_table_lookup(rtbl, apc),
                               realm));
}

/* Returns an array of pointers to TRP_RENTRY, length of array in n_out.
 * Caller must free the array (in the talloc NULL context), but must
 * not free its contents. */
TRP_RENTRY **trp_rtable_get_entries(TRP_RTABLE *rtbl, size_t *n_out)
{
  TRP_RENTRY **ret=NULL;
  TR_NAME **apc=NULL;
  size_t n_apc=0;
  TRP_RENTRY **apc_entries=NULL;
  size_t n_entries=0;
  size_t ii_ret=0;

  *n_out=trp_rtable_size(rtbl);
  if (*n_out==0)
    return NULL;

  ret=talloc_array(NULL, TRP_RENTRY *, *n_out);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_entries: unable to allocate return array.");
    *n_out=0;
    return NULL;
  }

  ii_ret=0; /* counts output entries */
  apc=trp_rtable_get_apcs(rtbl, &n_apc);
  while(n_apc--) {
    apc_entries=trp_rtable_get_apc_entries(rtbl, apc[n_apc], &n_entries);
    while (n_entries--)
      ret[ii_ret++]=apc_entries[n_entries];
    talloc_free(apc_entries);
  }
  talloc_free(apc);

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
TR_NAME **trp_rtable_get_apcs(TRP_RTABLE *rtbl, size_t *n_out)
{
  size_t len=g_hash_table_size(rtbl); /* known apcs are keys in top level hash table */
  size_t ii=0;
  GList *apcs=NULL;;
  GList *p=NULL;
  TR_NAME **ret=NULL;

  if (len==0) {
    *n_out=0;
    return NULL;
  }
    
  ret=talloc_array(NULL, TR_NAME *, len);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_apcs: unable to allocate return array.");
    *n_out=0;
    return NULL;
  }
  apcs=g_hash_table_get_keys(rtbl);
  for (ii=0,p=apcs; p!=NULL; ii++,p=g_list_next(p))
    ret[ii]=(TR_NAME *)p->data;

  g_list_free(apcs);

  *n_out=len;
  return ret;
}

/* Returns an array of pointers to TR_NAME, length of array in n_out.
 * Caller must free the array (in the talloc NULL context). */
TR_NAME **trp_rtable_get_apc_realms(TRP_RTABLE *rtbl, TR_NAME *apc, size_t *n_out)
{
  size_t ii=0;
  TRP_RTABLE *apc_tbl=g_hash_table_lookup(rtbl, apc);;
  GList *entries=NULL;
  GList *p=NULL;
  TR_NAME **ret=NULL;

  if (apc_tbl==NULL) {
    *n_out=0;
    return NULL;
  }
  *n_out=g_hash_table_size(apc_tbl); /* set output length */
  ret=talloc_array(NULL, TR_NAME *, *n_out);
  entries=g_hash_table_get_keys(apc_tbl);
  for (ii=0,p=entries; p!=NULL; ii++,p=g_list_next(p))
    ret[ii]=(TR_NAME *)p->data;

  g_list_free(entries);
  return ret;
}

/* Get all entries in an apc. Returns an array of pointers in NULL talloc context.
 * Caller must free this list with talloc_free, but must not free the entries in the
 * list.. */
TRP_RENTRY **trp_rtable_get_apc_entries(TRP_RTABLE *rtbl, TR_NAME *apc, size_t *n_out)
{
  size_t ii=0, jj=0;
  TR_NAME **realm=NULL;
  size_t n_realms=0;
  TRP_RENTRY **realm_entries=NULL;
  size_t n_entries=0;
  TRP_RENTRY **ret=NULL;
  size_t ii_ret=0;

  *n_out=trp_rtable_apc_size(rtbl, apc);
  if (*n_out==0)
    return NULL;

  ret=talloc_array(NULL, TRP_RENTRY *, *n_out);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_apc_entries: could not allocate return array.");
    *n_out=0;
    return NULL;
  }
  
  ii_ret=0; /* counts entries in the output array */
  realm=trp_rtable_get_apc_realms(rtbl, apc, &n_realms);
  for (ii=0; ii<n_realms; ii++) {
    realm_entries=trp_rtable_get_realm_entries(rtbl, apc, realm[ii], &n_entries);
    for (jj=0; jj<n_entries; jj++)
      ret[ii_ret++]=realm_entries[jj];
    talloc_free(realm_entries);
  }
  talloc_free(realm);

  if (ii_ret!=*n_out) {
    tr_crit("trp_rtable_get_apc_entries: found incorrect number of entries.");
    talloc_free(ret);
    *n_out=0;
    return NULL;
  }

  return ret;
}

/* Get all entries in an apc/realm. Returns an array of pointers in NULL talloc context.
 * Caller must free this list with talloc_free, but must not free the entries in the
 * list.. */
TRP_RENTRY **trp_rtable_get_realm_entries(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm, size_t *n_out)
{
  size_t ii=0;
  TRP_RENTRY **ret=NULL;
  TR_NAME **peer=NULL;

  peer=trp_rtable_get_apc_realm_peers(rtbl, apc, realm, n_out);
  ret=talloc_array(NULL, TRP_RENTRY *, *n_out);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_realm_entries: could not allocate return array.");
    talloc_free(peer);
    n_out=0;
    return NULL;
  }
  for (ii=0; ii<*n_out; ii++)
    ret[ii]=trp_rtable_get_entry(rtbl, apc, realm, peer[ii]);
  talloc_free(peer);
  return ret;
}

TR_NAME **trp_rtable_get_apc_realm_peers(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm, size_t *n_out)
{
  TR_NAME **ret=NULL;
  GHashTable *realm_tbl=NULL;
  GList *keys=NULL;
  GList *p=NULL;
  size_t ii=0;

  *n_out=trp_rtable_realm_size(rtbl, apc, realm);
  if (*n_out==0)
    return NULL;
  realm_tbl=trp_rtable_get_realm_table(rtbl, apc, realm);
  ret=talloc_array(NULL, TR_NAME *, *n_out);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_apc_realm_peers: could not allocate return array.");
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
TRP_RENTRY *trp_rtable_get_entry(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm, TR_NAME *peer)
{
  GHashTable *apc_tbl=NULL;
  GHashTable *realm_tbl=NULL;
  
  apc_tbl=g_hash_table_lookup(rtbl, apc);
  if (apc_tbl==NULL)
    return NULL;
  realm_tbl=g_hash_table_lookup(apc_tbl, realm);
  if (realm_tbl==NULL)
    return NULL;
  return g_hash_table_lookup(realm_tbl, peer); /* does not copy or increment ref count */
}
