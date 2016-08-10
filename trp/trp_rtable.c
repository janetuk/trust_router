#include <stdlib.h>

#include <glib.h>
#include <talloc.h>
#include <time.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <trp_rtable.h>
#include <tr_debug.h>

/* Note: be careful mixing talloc with glib. */

static int trp_route_destructor(void *obj)
{
  TRP_ROUTE *entry=talloc_get_type_abort(obj, TRP_ROUTE);
  if (entry->comm!=NULL)
    tr_free_name(entry->comm);
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

TRP_ROUTE *trp_route_new(TALLOC_CTX *mem_ctx)
{
  TRP_ROUTE *entry=talloc(mem_ctx, TRP_ROUTE);
  if (entry!=NULL) {
    entry->comm=NULL;
    entry->realm=NULL;
    entry->trust_router=NULL;
    entry->peer=NULL;
    entry->next_hop=NULL;
    entry->selected=0;
    entry->interval=0;
    entry->expiry=talloc(entry, struct timespec);
    if (entry->expiry==NULL) {
      talloc_free(entry);
      return NULL;
    }
    *(entry->expiry)=(struct timespec){0,0};
    entry->local=0;
    entry->triggered=0;
    talloc_set_destructor((void *)entry, trp_route_destructor);
  }
  return entry;
}

void trp_route_free(TRP_ROUTE *entry)
{
  if (entry!=NULL)
    talloc_free(entry);
}

void trp_route_set_comm(TRP_ROUTE *entry, TR_NAME *comm)
{
  if (entry->comm!=NULL)
    tr_free_name(entry->comm);
  entry->comm=comm;
}

TR_NAME *trp_route_get_comm(TRP_ROUTE *entry)
{
  return entry->comm;
}

TR_NAME *trp_route_dup_comm(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_comm(entry));
}

void trp_route_set_realm(TRP_ROUTE *entry, TR_NAME *realm)
{
  if (entry->realm!=NULL)
    tr_free_name(entry->realm);
  entry->realm=realm;
}

TR_NAME *trp_route_get_realm(TRP_ROUTE *entry)
{
  return entry->realm;
}

TR_NAME *trp_route_dup_realm(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_realm(entry));
}

void trp_route_set_trust_router(TRP_ROUTE *entry, TR_NAME *tr)
{
  if (entry->trust_router!=NULL)
    tr_free_name(entry->trust_router);
  entry->trust_router=tr;
}

TR_NAME *trp_route_get_trust_router(TRP_ROUTE *entry)
{
  return entry->trust_router;
}

TR_NAME *trp_route_dup_trust_router(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_trust_router(entry));
}

void trp_route_set_peer(TRP_ROUTE *entry, TR_NAME *peer)
{
  if (entry->peer!=NULL)
    tr_free_name(entry->peer);
  entry->peer=peer;
}

TR_NAME *trp_route_get_peer(TRP_ROUTE *entry)
{
  return entry->peer;
}

TR_NAME *trp_route_dup_peer(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_peer(entry));
}

void trp_route_set_metric(TRP_ROUTE *entry, unsigned int metric)
{
  entry->metric=metric;
}

unsigned int trp_route_get_metric(TRP_ROUTE *entry)
{
  return entry->metric;
}

void trp_route_set_next_hop(TRP_ROUTE *entry, TR_NAME *next_hop)
{
  if (entry->next_hop!=NULL)
    tr_free_name(entry->next_hop);
  entry->next_hop=next_hop;
}

TR_NAME *trp_route_get_next_hop(TRP_ROUTE *entry)
{
  return entry->next_hop;
}

TR_NAME *trp_route_dup_next_hop(TRP_ROUTE *entry)
{
  return tr_dup_name(trp_route_get_next_hop(entry));
}

void trp_route_set_selected(TRP_ROUTE *entry, int sel)
{
  entry->selected=sel;
}

int trp_route_is_selected(TRP_ROUTE *entry)
{
  return entry->selected;
}

void trp_route_set_interval(TRP_ROUTE *entry, int interval)
{
  entry->interval=interval;
}

int trp_route_get_interval(TRP_ROUTE *entry)
{
  return entry->interval;
}

/* copies incoming value, does not assume responsibility for freeing */
void trp_route_set_expiry(TRP_ROUTE *entry, struct timespec *exp)
{
  entry->expiry->tv_sec=exp->tv_sec;
  entry->expiry->tv_nsec=exp->tv_nsec;
}

struct timespec *trp_route_get_expiry(TRP_ROUTE *entry)
{
  return entry->expiry;
}

void trp_route_set_local(TRP_ROUTE *entry, int local)
{
  entry->local=local;
}

int trp_route_is_local(TRP_ROUTE *entry)
{
  return entry->local;
}

void trp_route_set_triggered(TRP_ROUTE *entry, int trig)
{
  entry->triggered=trig;
}

int trp_route_is_triggered(TRP_ROUTE *entry)
{
  return entry->triggered;
}


/* result must be freed with g_free */
static gchar *tr_name_to_g_str(const TR_NAME *n)
{
  gchar *s=g_strndup(n->buf, n->len);
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
 * Caller must free the array (in the talloc NULL context), but must
 * not free its contents. */
TRP_ROUTE **trp_rtable_get_entries(TRP_RTABLE *rtbl, size_t *n_out)
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

  ret=talloc_array(NULL, TRP_ROUTE *, *n_out);
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
 * list.. */
TRP_ROUTE **trp_rtable_get_realm_entries(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm, size_t *n_out)
{
  size_t ii=0;
  TRP_ROUTE **ret=NULL;
  TR_NAME **peer=NULL;

  peer=trp_rtable_get_comm_realm_peers(rtbl, comm, realm, n_out);
  ret=talloc_array(NULL, TRP_ROUTE *, *n_out);
  if (ret==NULL) {
    tr_crit("trp_rtable_get_realm_entries: could not allocate return array.");
    talloc_free(peer);
    n_out=0;
    return NULL;
  }
  for (ii=0; ii<*n_out; ii++)
    ret[ii]=trp_rtable_get_entry(rtbl, comm, realm, peer[ii]);
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

static char *timespec_to_str(struct timespec *ts)
{
  struct tm tm;
  char *s=NULL;

  if (localtime_r(&(ts->tv_sec), &tm)==NULL)
    return NULL;

  s=malloc(40); /* long enough to contain strftime result */
  if (s==NULL)
    return NULL;

  if (strftime(s, 40, "%F %T", &tm)==0) {
    free(s);
    return NULL;
  }
  return s;
}

TRP_ROUTE *trp_rtable_get_selected_entry(TRP_RTABLE *rtbl, TR_NAME *comm, TR_NAME *realm)
{
  size_t n=0;
  TRP_ROUTE **entry=trp_rtable_get_realm_entries(rtbl, comm, realm, &n);
  TRP_ROUTE *selected=NULL;

  if (n==0)
    return NULL;

  while(n-- && !trp_route_is_selected(entry[n])) { }
  selected=entry[n];
  talloc_free(entry);
  return selected;
}

/* Pretty print a route table entry to a newly allocated string. If sep is NULL,
 * returns comma+space separated string. */
char *trp_route_to_str(TALLOC_CTX *mem_ctx, TRP_ROUTE *entry, const char *sep)
{
  char *comm=tr_name_strdup(entry->comm);
  char *realm=tr_name_strdup(entry->realm);
  char *peer=tr_name_strdup(entry->peer);
  char *trust_router=tr_name_strdup(entry->trust_router);
  char *next_hop=tr_name_strdup(entry->next_hop);
  char *expiry=timespec_to_str(entry->expiry);
  char *result=NULL;

  if (sep==NULL)
    sep=", ";

  result=talloc_asprintf(mem_ctx,
                         "%s%s%s%s%s%s%u%s%s%s%s%s%u%s%u%s%s%s%u",
                         comm, sep,
                         realm, sep,
                         peer, sep,
                         entry->metric, sep,
                         trust_router, sep,
                         next_hop, sep,
                         entry->selected, sep,
                         entry->local, sep,
                         expiry, sep,
                         entry->triggered);
  free(comm);
  free(realm);
  free(peer);
  free(trust_router);
  free(next_hop);
  free(expiry);
  return result;
}

void trp_rtable_clear_triggered(TRP_RTABLE *rtbl)
{
  size_t n_entries=0;
  TRP_ROUTE **entries=trp_rtable_get_entries(rtbl, &n_entries);
  size_t ii=0;

  if (entries!=NULL) {
    for (ii=0; ii<n_entries; ii++)
      trp_route_set_triggered(entries[ii], 0);
    talloc_free(entries);
  }
}

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
