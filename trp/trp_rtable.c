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
  tr_debug("trp_rentry_new: %p", entry);
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

TRP_RTABLE *trp_rtable_new(void)
{
  GHashTable *new=g_hash_table_new_full(trp_tr_name_hash,
                                        trp_tr_name_equal,
                                        NULL, /* no need to free the key, it is part of the TRP_RENTRY */
                                        trp_rtable_destroy_table);
  tr_debug("trp_rtable_new: %p", new);
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
                                  NULL, /* no need to free the key */
                                  destroy);
    tr_debug("tr_rtbl_get_or_add_table: %p", val_tbl, trp_rtable_destroy_table);
    g_hash_table_insert(tbl, key, val_tbl);
  }
  return val_tbl;
}

void trp_rtable_add(TRP_RTABLE *rtbl, TRP_RENTRY *entry)
{
  GHashTable *apc_tbl=NULL;
  GHashTable *realm_tbl=NULL;

  apc_tbl=trp_rtbl_get_or_add_table(rtbl, entry->apc, trp_rtable_destroy_table);
  realm_tbl=trp_rtbl_get_or_add_table(apc_tbl, entry->realm, trp_rtable_destroy_rentry);
  g_hash_table_insert(realm_tbl, entry->peer, entry); /* destroys and replaces a duplicate */
}

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
  g_hash_table_remove(realm_tbl, entry->peer);
}

/* Get all entries in an apc. Returned as a talloc'ed array in the NULL
 * context. Caller should free these. */
size_t trp_rtable_get_apc(TRP_RTABLE *rtbl, TR_NAME *apc, TRP_RENTRY **ret)
{
  GHashTable *apc_tbl=NULL;
  size_t len=0; /* length of return array */
  size_t ii=0;
  GList *realms=NULL;
  GList *realm_entries=NULL;
  GList *p1=NULL, *p2=NULL;

  apc_tbl=g_hash_table_lookup(rtbl, apc);
  if (apc_tbl==NULL)
    return 0;

  realms=g_hash_table_get_values(apc_tbl);
  /* make two passes: first count the entries, then allocate and populate the output array */
  for (p1=realms; p1!=NULL; p1=g_list_next(p1))
    len+=g_hash_table_size(p1->data);
  if (len==0) {
    g_list_free(realms);
    return 0;
  }

  *ret=talloc_array(NULL, TRP_RENTRY, len);
  if (*ret==NULL) {
    tr_crit("trp_rtable_get_apc: could not allocate return array.");
    g_list_free(realms);
    return 0;
  }

  ii=0;
  for (p1=realms; p1!=NULL; p1=g_list_next(p1)) {
    realm_entries=g_hash_table_get_values(p1->data);
    for (p2=realm_entries; p2!=NULL; p2=g_list_next(p2)) {
      memcpy(*ret+ii, p2->data, sizeof(TRP_RENTRY));
      ii++;
    }
    g_list_free(realm_entries);
  }

  g_list_free(realms);
  return len;
}

/* Get all entries in an apc/realm. Returns as a talloc'ed array in
 * the NULL context via .  Caller must free these. */
size_t trp_rtable_get_realm(TRP_RTABLE *rtbl, TR_NAME *apc, TR_NAME *realm, TRP_RENTRY **ret)
{
  GHashTable *apc_tbl=NULL;
  GHashTable *realm_tbl=NULL;
  size_t len=0;
  size_t ii=0;
  GList *entries=NULL;
  GList *p=NULL;

  apc_tbl=g_hash_table_lookup(rtbl, apc);
  if (apc_tbl==NULL)
    return 0;
  realm_tbl=g_hash_table_lookup(apc_tbl, realm);
  if (realm_tbl==NULL)
    return 0;
  entries=g_hash_table_get_values(realm_tbl);
  len=g_hash_table_size(realm_tbl);
  *ret=talloc_array(NULL, TRP_RENTRY, len);
  if (*ret==NULL) {
    tr_crit("trp_rtable_get_realm: could not allocate return array.");
    return 0;
  }
  for (ii=0,p=entries; p!=NULL; ii++,p=g_list_next(p))
    memcpy(*ret+ii, p->data, sizeof(TRP_RENTRY));
  g_list_free(entries);
  return len;
}

/* Gets a single entry, in the NULL talloc context. Caller must free. */
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
  return (TRP_RENTRY *)g_hash_table_lookup(realm_tbl, peer);
}
