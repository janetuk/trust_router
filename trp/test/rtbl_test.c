#include <stdio.h>
#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_rtable.h>

char *apc[]={"apc1", "apc2", "apc3"};
size_t n_apc=sizeof(apc)/sizeof(apc[0]);
char *realm[]={"realm1", "realm2", "realm3"};
size_t n_realm=sizeof(realm)/sizeof(realm[0]);
char *peer[]={"peer1", "peer2", "peer3"};
size_t n_peer=sizeof(peer)/sizeof(peer[0]);

static void populate_rtable(TRP_RTABLE *table)
{
  TRP_RENTRY *entry=NULL;
  size_t ii=0, jj=0, kk=0;

  for (ii=0; ii<n_apc; ii++) {
    for (jj=0; jj<n_realm; jj++) {
      for (kk=0; kk<n_peer; kk++) {
        entry=trp_rentry_new(NULL);
        trp_rentry_set_apc(entry, tr_new_name(apc[ii]));
        trp_rentry_set_realm(entry, tr_new_name(realm[jj]));
        trp_rentry_set_trust_router(entry, tr_new_name(realm[jj]));
        trp_rentry_set_peer(entry, tr_new_name(peer[kk]));
        trp_rentry_set_metric(entry, ii+jj+kk);
        trp_rentry_set_next_hop(entry, tr_new_name(peer[kk]));
        trp_rtable_add(table, entry);
        entry=NULL; /* entry belongs to the table now */
      }
    }
  }
}

static void print_rentry(TRP_RENTRY *entry)
{
  printf("apc: %s\n", trp_rentry_get_apc(entry)->buf);
  printf("realm: %s\n", trp_rentry_get_realm(entry)->buf);
  printf("trust_router: %s\n", trp_rentry_get_trust_router(entry)->buf);
  printf("peer: %s\n", trp_rentry_get_peer(entry)->buf);
  printf("next_hop: %s\n", trp_rentry_get_next_hop(entry)->buf);
  printf("metric: %d\n", trp_rentry_get_metric(entry));
  printf("\n");
}

static void print_rtable(TRP_RTABLE *table)
{
  size_t ii=0, jj=0;
  TRP_RENTRY *apc_entry=NULL;
  size_t len=0;
  TR_NAME *n=0;

  for (ii=0; ii<n_apc; ii++) {
    len=trp_rtable_get_apc(table, n=tr_new_name(apc[ii]), &apc_entry);
    tr_free_name(n); n=NULL;
    for (jj=0; jj<len; jj++)
      print_rentry(apc_entry+jj);
    talloc_free(apc_entry);
  }
}

int main(void)
{
  TRP_RTABLE *table=NULL;
  table=trp_rtable_new();
  populate_rtable(table);
  print_rtable(table);
  trp_rtable_free(table);
  return 0;
}
