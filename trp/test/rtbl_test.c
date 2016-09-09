#include <stdio.h>
#include <talloc.h>
#include <string.h>
#include <assert.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <trp_rtable.h>

char *apc[]={"apc1", "apc2", "apc3"};
size_t n_apc=sizeof(apc)/sizeof(apc[0]);
char *realm[]={"realm1", "realm2", "realm3"};
size_t n_realm=sizeof(realm)/sizeof(realm[0]);
char *peer[]={"peer1", "peer2", "peer3"};
size_t n_peer=sizeof(peer)/sizeof(peer[0]);

static unsigned int metric1(size_t a, size_t b, size_t c)
{
  return a+b+c;
}

static unsigned int metric2(size_t a, size_t b, size_t c)
{
  return a+b+c+25;
}

static unsigned int metric3(size_t a, size_t b, size_t c)
{
  return a*(b+c)+b*c;
}

static void populate_rtable(TRP_RTABLE *table, unsigned int (*metric)(size_t, size_t, size_t))
{
  TRP_ROUTE *entry=NULL;
  size_t ii=0, jj=0, kk=0;
  struct timespec ts={0,0};

  for (ii=0; ii<n_apc; ii++) {
    for (jj=0; jj<n_realm; jj++) {
      for (kk=0; kk<n_peer; kk++) {
        entry=trp_route_new(NULL);
        trp_route_set_comm(entry, tr_new_name(apc[ii]));
        trp_route_set_realm(entry, tr_new_name(realm[jj]));
        trp_route_set_trust_router(entry, tr_new_name(realm[jj]));
        trp_route_set_peer(entry, tr_new_name(peer[kk]));
        trp_route_set_metric(entry, metric(ii,jj,kk));
        trp_route_set_next_hop(entry, tr_new_name(peer[kk]));
        ts=(struct timespec){jj+1,ii+kk+1};
        trp_route_set_expiry(entry, &ts);
        trp_rtable_add(table, entry);
        entry=NULL; /* entry belongs to the table now */
      }
    }
  }
}

static void verify_rtable(TRP_RTABLE *table, unsigned int (*metric)(size_t, size_t, size_t))
{
  TRP_ROUTE *entry=NULL;
  size_t ii=0, jj=0, kk=0;
  size_t len=0;
  TR_NAME *apc_n, *realm_n, *peer_n;

  for (ii=0; ii<n_apc; ii++) {
    for (jj=0; jj<n_realm; jj++) {
      for (kk=0; kk<n_peer; kk++) {
        apc_n=tr_new_name(apc[ii]);
        realm_n=tr_new_name(realm[jj]);
        peer_n=tr_new_name(peer[kk]);
        entry=trp_rtable_get_entry(table, apc_n, realm_n, peer_n);
        tr_free_name(apc_n);
        tr_free_name(realm_n);
        tr_free_name(peer_n);

        assert(entry!=NULL);

        len=trp_route_get_comm(entry)->len;
        assert(len==strlen(apc[ii]));
        assert(0==strncmp(trp_route_get_comm(entry)->buf, apc[ii], len));

        len=trp_route_get_realm(entry)->len;
        assert(len==strlen(realm[jj]));
        assert(0==strncmp(trp_route_get_realm(entry)->buf, realm[jj], len));
        
        len=trp_route_get_peer(entry)->len;
        assert(len==strlen(peer[kk]));
        assert(0==strncmp(trp_route_get_peer(entry)->buf, peer[kk], len));
        
        len=trp_route_get_trust_router(entry)->len;
        assert(len==strlen(realm[jj]));
        assert(0==strncmp(trp_route_get_trust_router(entry)->buf, realm[jj], len));

        assert(trp_route_get_metric(entry)==metric(ii,jj,kk));

        len=trp_route_get_next_hop(entry)->len;
        assert(len==strlen(peer[kk]));
        assert(0==strncmp(trp_route_get_next_hop(entry)->buf, peer[kk], len));

        assert(trp_route_is_selected(entry)==0);
        assert(trp_route_get_expiry(entry)->tv_sec==jj+1);
        assert(trp_route_get_expiry(entry)->tv_nsec==ii+kk+1);

        printf("{%s %s %s} entry OK!\n", apc[ii], realm[jj], peer[kk]);
      }
    }
  }
}

static int is_in(char *a, char *b[], size_t n_b)
{
  size_t count=0;

  while (n_b--) {
    if (0==strcmp(a, b[n_b]))
      count++;
  }
  return count;
}
static void verify_apc_list(TRP_RTABLE *table)
{
  size_t n=0;
  TR_NAME **apcs_found=trp_rtable_get_comms(table, &n);
  assert(n==n_apc);
  while(n--)
    assert(1==is_in(apcs_found[n]->buf, apc, n_apc));
}

static void verify_apc_realm_lists(TRP_RTABLE *table)
{
  size_t n=0, ii=0;
  TR_NAME *apc_n=NULL, **realms_found=NULL;

  for (ii=0; ii<n_apc; ii++) {
    apc_n=tr_new_name(apc[ii]);
    realms_found=trp_rtable_get_comm_realms(table, apc_n, &n);
    tr_free_name(apc_n);
    assert(n==n_realm);
    while (n--)
      assert(1==is_in(realms_found[n]->buf, realm, n_realm));
    talloc_free(realms_found);
    printf("APC %s ok!\n", apc[ii]);
  }
}

static void verify_get_apc_entries(TRP_RTABLE *table)
{
  size_t n=0, ii=0;
  TRP_ROUTE **apc_entries=NULL;
  TR_NAME *apc_n=NULL;

  for (ii=0; ii<n_apc; ii++) {
    apc_n=tr_new_name(apc[ii]);
    apc_entries=trp_rtable_get_comm_entries(table, apc_n, &n);
    tr_free_name(apc_n);
    assert(n==n_realm*n_peer);
    while (n--) {
      assert(0==strncmp(trp_route_get_comm(apc_entries[n])->buf,
                        apc[ii],
                        trp_route_get_comm(apc_entries[n])->len));
      assert(1==is_in(trp_route_get_realm(apc_entries[n])->buf, realm, n_realm));
      assert(1==is_in(trp_route_get_peer(apc_entries[n])->buf, peer, n_peer));
    }
    printf("APC %s ok!\n", apc[ii]);
    talloc_free(apc_entries);
  }
}

static void verify_get_realm_entries(TRP_RTABLE *table)
{
  size_t n=0, ii=0, jj=0;
  TRP_ROUTE **realm_entries=NULL;
  TR_NAME *apc_n=NULL, *realm_n=NULL;

  for (ii=0; ii<n_apc; ii++) {
    for (jj=0; jj<n_realm; jj++) {
      apc_n=tr_new_name(apc[ii]);
      realm_n=tr_new_name(realm[jj]);
      realm_entries=trp_rtable_get_realm_entries(table, apc_n, realm_n, &n);
      tr_free_name(apc_n);
      tr_free_name(realm_n);
      assert(n==n_peer);
      while (n--) {
        assert(0==strncmp(trp_route_get_comm(realm_entries[n])->buf,
                          apc[ii],
                          trp_route_get_comm(realm_entries[n])->len));
        assert(0==strncmp(trp_route_get_realm(realm_entries[n])->buf,
                          realm[jj],
                          trp_route_get_realm(realm_entries[n])->len));
        assert(1==is_in(trp_route_get_peer(realm_entries[n])->buf, peer, n_peer));
      }
      printf("APC %s realm %s ok!\n", apc[ii], realm[jj]);
      talloc_free(realm_entries);
    }
  }
}

/* doesn't work if c not in a */
static size_t get_index(char *c, char **a, size_t n_a)
{
  while(n_a--) {
    if (0==strcmp(c, a[n_a]))
      return n_a;
  }
  return 0;
}

static void update_metric(TRP_RTABLE *table, unsigned int (*new_metric)(size_t, size_t, size_t))
{
  TRP_ROUTE **entries=NULL;
  size_t n=0, ii=0,jj=0,kk=0;

  entries=trp_rtable_get_entries(table, &n);
  while (n--) {
    ii=get_index(trp_route_get_comm(entries[n])->buf, apc, n_apc);
    jj=get_index(trp_route_get_realm(entries[n])->buf, realm, n_realm);
    kk=get_index(trp_route_get_peer(entries[n])->buf, peer, n_peer);
    trp_route_set_metric(entries[n],
                          new_metric(ii,jj,kk));
  }
  talloc_free(entries);
}

static void remove_entries(TRP_RTABLE *table)
{
  size_t n=trp_rtable_size(table);
  size_t ii,jj,kk;
  TR_NAME *apc_n, *realm_n, *peer_n;
  TRP_ROUTE *entry=NULL;

  for (ii=0; ii<n_apc; ii++) {
    for (jj=0; jj<n_realm; jj++) {
      for (kk=0; kk<n_realm; kk++) {
        apc_n=tr_new_name(apc[ii]);
        realm_n=tr_new_name(realm[jj]);
        peer_n=tr_new_name(peer[kk]);
        entry=trp_rtable_get_entry(table, apc_n, realm_n, peer_n);
        assert(entry !=NULL);
        tr_free_name(apc_n);
        tr_free_name(realm_n);
        tr_free_name(peer_n);
        trp_rtable_remove(table, entry);
        entry=NULL;
        assert(trp_rtable_size(table)==--n);
      }
    }
  }
}


static void print_rtable(TRP_RTABLE *table)
{
  char *s=trp_rtable_to_str(NULL, table, NULL, NULL);
  printf(s);
  talloc_free(s);
}

int main(void)
{
  TRP_RTABLE *table=NULL;
  table=trp_rtable_new();
  populate_rtable(table, metric1);
  print_rtable(table);

  printf("\nVerifying routing table...\n");
  verify_rtable(table, metric1);
  printf("                         ...success!\n");

  printf("\nVerifying APC list...\n");
  verify_apc_list(table);
  printf("                    ...success!\n");

  printf("\nVerifying APC realm lists...\n");
  verify_apc_realm_lists(table);
  printf("                    ...success!\n");

  printf("\nVerifying APC entry lists...\n");
  verify_get_apc_entries(table);
  printf("                           ...success!\n");

  printf("\nVerifying realm entry lists...\n");
  verify_get_realm_entries(table);
  printf("                              ...success!\n");

  printf("\nVerifying table value update...\n");
  update_metric(table, metric2); /* changes the metric value in each element in-place */
  verify_rtable(table, metric2);
  printf("                              ...success!\n");

  printf("\nVerifying element replacement...\n");
  populate_rtable(table, metric3); /* replaces all the elements with new ones */
  verify_rtable(table, metric3);
  printf("                               ...success!\n");

  printf("\nVerifying element removal...\n");
  remove_entries(table);
  print_rtable(table);
  printf("                           ...success!\n");

  printf("\nRepopulating table...\n");
  populate_rtable(table, metric3);
  verify_rtable(table, metric3);
  printf("                               ...success!\n");

  trp_rtable_free(table);
  return 0;
}
