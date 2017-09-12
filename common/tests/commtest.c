#include <talloc.h>
#include <assert.h>
#include <jansson.h>

#include <tr_apc.h>
#include <tr_comm.h>
#include <tr_rp.h>
#include <tr_name_internal.h>

/**********************************************************************/
/* APC test stuff */
struct apc_entry {
  const char *id; /* only allows a single entry for now */
};

static TR_APC *apc_entry_to_apc(TALLOC_CTX *mem_ctx, struct apc_entry *ae)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_APC *apcs=NULL;

  apcs=tr_apc_new(tmp_ctx);
  if (apcs!=NULL) {
    tr_apc_set_id(apcs, tr_new_name(ae->id));
    talloc_steal(mem_ctx, apcs);
  }

  talloc_free(tmp_ctx); 
  return apcs;
}

/**********************************************************************/
/* TR_COMM test stuff */

struct comm_entry {
  const char *id;
  TR_COMM_TYPE type;
  struct apc_entry *apcs;
};

static TR_COMM *comm_entry_to_comm(TALLOC_CTX *mem_ctx, struct comm_entry *ce)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_COMM *comm=tr_comm_new(tmp_ctx);

  if (comm!=NULL) {
    tr_comm_set_id(comm, tr_new_name(ce->id));
    tr_comm_set_type(comm, ce->type);
    if (ce->apcs!=NULL)
      tr_comm_set_apcs(comm, apc_entry_to_apc(tmp_ctx, ce->apcs));

    if ((tr_comm_get_id(comm)==NULL) ||
        ((ce->apcs!=NULL)&&(tr_comm_get_apcs(comm)==NULL)))
      comm=NULL; /* it's in tmp_ctx, so will be freed */
    else
      talloc_steal(mem_ctx, comm);
  }

  talloc_free(tmp_ctx); 
  return comm;
}

static int add_comm_set(TR_COMM_TABLE *ctab, struct comm_entry *entries)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct comm_entry *this=NULL;
  size_t ii=0;
  TR_COMM *new=NULL;
  int rc=-1;

  for (this=entries,ii=0; this->id!=NULL; this++, ii++) {
    new=comm_entry_to_comm(tmp_ctx, this);
    if (new==NULL) {
      printf("Error creating community %u.\n", (unsigned int)ii+1);
      rc=1;
      goto cleanup;
    }
    tr_comm_table_add_comm(ctab, new);
  }
  /* success */
  rc=0;

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

static int verify_comm_set(TR_COMM_TABLE *ctab, struct comm_entry *entries)
{
  struct comm_entry *this=NULL;
  TR_COMM *comm=NULL;
  TR_NAME *this_id=NULL;

  for (this=entries; this->id!=NULL; this++) {
    this_id=tr_new_name(this->id);
    comm=tr_comm_table_find_comm(ctab, this_id);
    tr_free_name(this_id); this_id=NULL;
    
    if (comm==NULL) {
      printf("Error, community %s missing from community table.\n", this->id);
      return -1;
    }
    if (tr_comm_get_type(comm)!=this->type) {
      printf("Error, community %s has wrong type (was %s, expected %s).\n",
             this->id,
             tr_comm_type_to_str(tr_comm_get_type(comm)),
             tr_comm_type_to_str(this->type));
      return -1;
    }
    /* TODO: verify apcs */
  }
  return 0;
}

/* removes entry n from ctab */
static int remove_comm_set_member(TR_COMM_TABLE *ctab, struct comm_entry *entries, size_t n)
{
  TR_NAME *comm_name=tr_new_name(entries[n].id);
  TR_COMM *comm=tr_comm_table_find_comm(ctab, comm_name);
  TR_COMM *comm2=NULL;

  if (comm==NULL) {
    printf("Can't remove community %s, not in table.\n", entries[n].id);
    tr_free_name(comm_name);
    return 1;
  }
  
  tr_comm_table_remove_comm(ctab, comm);
  comm2=tr_comm_table_find_comm(ctab, comm_name);
  if (comm2!=NULL) {
    printf("Community %s still in table after removal.\n", entries[n].id);
    tr_comm_free(comm);
    tr_free_name(comm_name);
    return 2;
  }

  tr_comm_free(comm);
  tr_free_name(comm_name);
  return 0;
}

/**********************************************************************/
/* TR_RP_REALM test stuff */

struct rp_realm_entry {
  const char *id;
};

static TR_RP_REALM *rp_realm_entry_to_rp_realm(TALLOC_CTX *mem_ctx, struct rp_realm_entry *re)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_RP_REALM *realm=NULL;

  realm=tr_rp_realm_new(tmp_ctx);
  if (realm!=NULL) {
    tr_rp_realm_set_id(realm, tr_new_name(re->id));
    talloc_steal(mem_ctx, realm);
  }

  talloc_free(tmp_ctx); 
  return realm;
}

static int add_rp_realm_set(TR_COMM_TABLE *ctab, struct rp_realm_entry *entries)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct rp_realm_entry *this=NULL;
  TR_RP_REALM *realm=NULL;
  int rc=-1;

  for (this=entries; this->id!=NULL; this++) {
    realm=rp_realm_entry_to_rp_realm(tmp_ctx, this);
    if (realm==NULL) {
      printf("Error creating RP realm %s.\n", this->id);
      rc=1;
      goto cleanup;
    }
    tr_comm_table_add_rp_realm(ctab, realm);
  }
  rc=0;

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

static int verify_rp_realm_set(TR_COMM_TABLE *ctab, struct rp_realm_entry *entries)
{
  struct rp_realm_entry *this=NULL;
  TR_RP_REALM *rp_realm=NULL;
  TR_NAME *this_id=NULL;

  for (this=entries; this->id!=NULL; this++) {
    this_id=tr_new_name(this->id);
    rp_realm=tr_comm_table_find_rp_realm(ctab, this_id);
    tr_free_name(this_id); this_id=NULL;
    
    if (rp_realm==NULL) {
      printf("Error, RP realm %s missing from community table.\n", this->id);
      return -1;
    }
  }
  return 0;
}

/* removes entry n from ctab */
static int remove_rp_realm_set_member(TR_COMM_TABLE *ctab, struct rp_realm_entry *entries, size_t n)
{
  TR_NAME *rp_realm_name=tr_new_name(entries[n].id);
  TR_RP_REALM *rp_realm=tr_comm_table_find_rp_realm(ctab, rp_realm_name);
  TR_RP_REALM *rp_realm2=NULL;

  if (rp_realm==NULL) {
    printf("Can't remove RP realm %s, not in table.\n", entries[n].id);
    tr_free_name(rp_realm_name);
    return 1;
  }
  
  tr_comm_table_remove_rp_realm(ctab, rp_realm);
  rp_realm2=tr_comm_table_find_rp_realm(ctab, rp_realm_name);
  if (rp_realm2!=NULL) {
    printf("RP realm %s still in table after removal.\n", entries[n].id);
    tr_rp_realm_free(rp_realm);
    tr_free_name(rp_realm_name);
    return 2;
  }

  tr_rp_realm_free(rp_realm);
  tr_free_name(rp_realm_name);
  return 0;
}

/**********************************************************************/
/* TR_AAA_SERVER test stuff */

struct aaa_entry {
  const char *hostname; /* only supports one for testing right now */
};

static TR_AAA_SERVER *aaa_entry_to_aaa_server(TALLOC_CTX *mem_ctx, struct aaa_entry *ae)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_AAA_SERVER *aaa=tr_aaa_server_new(tmp_ctx, tr_new_name(ae->hostname));

  if ((aaa==NULL) || (aaa->hostname==NULL))
    aaa=NULL;
  else
    talloc_steal(mem_ctx, aaa);

  talloc_free(tmp_ctx); 
  return aaa;
}


/**********************************************************************/
/* TR_IDP_REALM test stuff */

struct idp_realm_entry {
  const char *id;
  struct aaa_entry *aaa_servers;
  struct apc_entry *apcs;
};

static TR_IDP_REALM *idp_realm_entry_to_idp_realm(TALLOC_CTX *mem_ctx, struct idp_realm_entry *re)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_IDP_REALM *realm=NULL;

  realm=tr_idp_realm_new(tmp_ctx);
  if (realm!=NULL) {
    tr_idp_realm_set_id(realm, tr_new_name(re->id));
    realm->aaa_servers=aaa_entry_to_aaa_server(realm, re->aaa_servers);
    if (realm->aaa_servers==NULL)
      realm=NULL; /* still in tmp_ctx so will be freed */
    else {
      tr_idp_realm_set_apcs(realm, apc_entry_to_apc(tmp_ctx, re->apcs));
      if (tr_idp_realm_get_apcs(realm)==NULL)
        realm=NULL;
    }
  }

  if (realm!=NULL)
    talloc_steal(mem_ctx, realm);

  talloc_free(tmp_ctx); 
  return realm;
}

static int add_idp_realm_set(TR_COMM_TABLE *ctab, struct idp_realm_entry *entries)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct idp_realm_entry *this=NULL;
  TR_IDP_REALM *realm=NULL;
  int rc=-1;

  for (this=entries; this->id!=NULL; this++) {
    realm=idp_realm_entry_to_idp_realm(tmp_ctx, this);
    if (realm==NULL) {
      printf("Error creating IDP realm %s.\n", this->id);
      rc=1;
      goto cleanup;
    }
    tr_comm_table_add_idp_realm(ctab, realm);
  }
  rc=0;

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

static int verify_idp_realm_set(TR_COMM_TABLE *ctab, struct idp_realm_entry *entries)
{
  struct idp_realm_entry *this=NULL;
  TR_IDP_REALM *idp_realm=NULL;
  TR_NAME *this_id=NULL;

  for (this=entries; this->id!=NULL; this++) {
    this_id=tr_new_name(this->id);
    idp_realm=tr_comm_table_find_idp_realm(ctab, this_id);
    tr_free_name(this_id); this_id=NULL;
    
    if (idp_realm==NULL) {
      printf("Error, IDP realm %s missing from community table.\n", this->id);
      return -1;
    }
  }
  return 0;
}

/* removes entry n from ctab */
static int remove_idp_realm_set_member(TR_COMM_TABLE *ctab, struct idp_realm_entry *entries, size_t n)
{
  TR_NAME *idp_realm_name=tr_new_name(entries[n].id);
  TR_IDP_REALM *idp_realm=tr_comm_table_find_idp_realm(ctab, idp_realm_name);
  TR_IDP_REALM *idp_realm2=NULL;

  if (idp_realm==NULL) {
    printf("Can't remove IDP realm %s, not in table.\n", entries[n].id);
    tr_free_name(idp_realm_name);
    return 1;
  }
  
  tr_comm_table_remove_idp_realm(ctab, idp_realm);
  idp_realm2=tr_comm_table_find_idp_realm(ctab, idp_realm_name);
  if (idp_realm2!=NULL) {
    printf("IDP realm %s still in table after removal.\n", entries[n].id);
    tr_idp_realm_free(idp_realm);
    tr_free_name(idp_realm_name);
    return 2;
  }

  tr_idp_realm_free(idp_realm);
  tr_free_name(idp_realm_name);
  return 0;
}

/**********************************************************************/
/* Community Membership test stuff */

struct comm_memb_entry {
  TR_REALM_ROLE role;
  const char *realm_name;
  const char *comm_name;
  const char *origin;
  /* TODO: test provenance */
};

/* add an existing realm to an existing community (these must
 * exist in the community table lists) */
static int add_comm_membership(TR_COMM_TABLE *ctab, struct comm_memb_entry *entry)
{
  TR_NAME *comm_name=tr_new_name(entry->comm_name);
  TR_NAME *realm_name=tr_new_name(entry->realm_name);
  TR_COMM *comm=tr_comm_table_find_comm(ctab, comm_name);
  TR_RP_REALM *rp_realm=(entry->role==TR_ROLE_RP)?(tr_comm_table_find_rp_realm(ctab, realm_name)):(NULL);
  TR_IDP_REALM *idp_realm=(entry->role==TR_ROLE_IDP)?(tr_comm_table_find_idp_realm(ctab, realm_name)):(NULL);
  json_t *prov=NULL;
  
  if ((comm==NULL) || ((rp_realm==NULL)&&(idp_realm==NULL)))
    return 1;

  prov=json_array();
  if (entry->origin!=NULL)
    json_array_append(prov, json_string(entry->origin));

  switch (entry->role) {
  case TR_ROLE_IDP:
    tr_comm_add_idp_realm(ctab, comm, idp_realm, 0, prov, NULL); /* Expiry!? */
    break;
  case TR_ROLE_RP:
    tr_comm_add_rp_realm(ctab, comm, rp_realm, 0, prov, NULL); /* Expiry!? */
    break;
  default:
    return 2;
  }
  
  return 0;
}

static int add_member_set(TR_COMM_TABLE *ctab, struct comm_memb_entry *entries)
{
  struct comm_memb_entry *this=NULL;

  for (this=entries; this->role!=TR_ROLE_UNKNOWN; this++) {
    if (0!=add_comm_membership(ctab, this)) {
      printf("Error adding %s realm %s to community %s (origin %s).\n",
             (this->role==TR_ROLE_RP)?"RP":"IDP",
             this->realm_name,
             this->comm_name,
             (this->origin!=NULL)?(this->origin):"null");
      return 1;
    }
  }
  return 0;
}

static int remove_membership(TR_COMM_TABLE *ctab, struct comm_memb_entry *entries, size_t n)
{
  TR_NAME *realm_name=tr_new_name(entries[n].realm_name);
  TR_NAME *comm_name=tr_new_name(entries[n].comm_name);
  TR_NAME *origin=(entries[n].origin!=NULL)?(tr_new_name(entries[n].origin)):NULL;
  TR_COMM_MEMB *memb=NULL;
  int rc=-1;

  switch (entries[n].role) {
  case TR_ROLE_IDP:
    memb=tr_comm_table_find_idp_memb_origin(ctab, realm_name, comm_name, origin);
    break;
  case TR_ROLE_RP:
    memb=tr_comm_table_find_rp_memb_origin(ctab, realm_name, comm_name, origin);
    break;
  default:
    rc=1;
    goto cleanup;
  }

  if (memb==NULL) {
    printf("%s realm %s not in comm %s from origin %s, can't remove membership.\n",
           (entries[n].role==TR_ROLE_RP)?"RP":"IDP",
           entries[n].realm_name,
           entries[n].comm_name,
           (entries[n].origin!=NULL)?(entries[n].origin):"null");
    rc=2;
    goto cleanup;
  }
  tr_comm_table_remove_memb(ctab, memb);
  tr_comm_memb_free(memb);
  rc=0;

cleanup:
  tr_free_name(realm_name);
  tr_free_name(comm_name);
  if (origin!=NULL)
    tr_free_name(origin);
  return rc;
}

/**********************************************************************/
/* Test data */

struct apc_entry apc_1={ "apc" };

struct comm_entry comm_set_1[]={
  { "apc", TR_COMM_APC, NULL },
  { "comm 1", TR_COMM_COI, &apc_1 },
  { "comm 2", TR_COMM_COI, &apc_1 },
  { NULL }
};

struct rp_realm_entry rp_realm_set_1[]={
  { "rp 1" },
  { "rp 2" },
  { "rp 3" },
  { NULL }
};

struct aaa_entry aaa_1= { "aaa 1" };
struct aaa_entry aaa_2= { "aaa 2" };
struct aaa_entry aaa_3= { "aaa 3" };

struct idp_realm_entry idp_realm_set_1[]={
  { "idp 1", &aaa_1, &apc_1 },
  { "idp 2", &aaa_2, &apc_1 },
  { "idp 3", &aaa_3, &apc_1 },
  { NULL }
};

struct comm_memb_entry member_set_1[]={
  { TR_ROLE_RP, "rp 1", "apc", NULL },
  { TR_ROLE_RP, "rp 2", "apc", NULL },
  { TR_ROLE_RP, "rp 3", "apc", NULL },
  { TR_ROLE_IDP, "idp 1", "apc", NULL },
  { TR_ROLE_IDP, "idp 2", "apc", NULL },
  { TR_ROLE_IDP, "idp 3", "apc", NULL },
  { TR_ROLE_RP, "rp 1", "comm 1", NULL },
  { TR_ROLE_RP, "rp 2", "comm 1", NULL },
  { TR_ROLE_RP, "rp 2", "comm 1", "peer 1" },
  { TR_ROLE_RP, "rp 2", "comm 1", "peer 2" },
  { TR_ROLE_IDP, "idp 1", "comm 1", NULL },
  { TR_ROLE_IDP, "idp 1", "comm 1", "peer 1" },
  { TR_ROLE_IDP, "idp 1", "comm 1", "peer 2" },
  { TR_ROLE_IDP, "idp 2", "comm 1", NULL },
  { TR_ROLE_RP, "rp 1", "comm 2", NULL },
  { TR_ROLE_RP, "rp 2", "comm 2", NULL },
  { TR_ROLE_RP, "rp 2", "comm 2", "peer 1" },
  { TR_ROLE_RP, "rp 2", "comm 2", "peer 2" },
  { TR_ROLE_IDP, "idp 1", "comm 2", NULL },
  { TR_ROLE_IDP, "idp 1", "comm 2", "peer 1" },
  { TR_ROLE_IDP, "idp 1", "comm 2", "peer 2" },
  { TR_ROLE_IDP, "idp 2", "comm 2", NULL },
  { TR_ROLE_UNKNOWN }
};


/**********************************************************************/
/* Test routines */

/* the first few tests here insert a few things into the community table (comms,
 * rp_realms, or idp_realms), then verify that they're all there. They
 * then remove them in various orders, put them back, try removing
 * things that are not present, etc. */

static int community_test(void)
{
  TALLOC_CTX *mem_ctx=talloc_new(NULL);
  TR_COMM_TABLE *ctab=tr_comm_table_new(mem_ctx);

  assert(0==tr_comm_table_size(ctab));

  /* add communities */
  assert(ctab!=NULL);
  assert(0==add_comm_set(ctab, comm_set_1));
  assert(3==tr_comm_table_size(ctab));
  assert(0==verify_comm_set(ctab, comm_set_1));

  /* remove */
  assert(0==remove_comm_set_member(ctab, comm_set_1, 0));
  assert(2==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 1));
  assert(1==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 2));
  assert(0==tr_comm_table_size(ctab));
  
  /* add communities */
  assert(ctab!=NULL);
  assert(0==add_comm_set(ctab, comm_set_1));
  assert(3==tr_comm_table_size(ctab));
  assert(0==verify_comm_set(ctab, comm_set_1));

  /* remove */
  assert(0==remove_comm_set_member(ctab, comm_set_1, 0));
  assert(2==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 2));
  assert(1==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 1));
  assert(0==tr_comm_table_size(ctab));
  
  /* add communities */
  assert(ctab!=NULL);
  assert(0==add_comm_set(ctab, comm_set_1));
  assert(3==tr_comm_table_size(ctab));
  assert(0==verify_comm_set(ctab, comm_set_1));

  /* remove */
  assert(0==remove_comm_set_member(ctab, comm_set_1, 1));
  assert(2==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 0));
  assert(1==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 2));
  assert(0==tr_comm_table_size(ctab));
  
  assert(1==remove_comm_set_member(ctab, comm_set_1, 1)); /* should not be in the table */
  assert(0==tr_comm_table_size(ctab));

  /* add communities */
  assert(ctab!=NULL);
  assert(0==add_comm_set(ctab, comm_set_1));
  assert(3==tr_comm_table_size(ctab));
  assert(0==verify_comm_set(ctab, comm_set_1));

  /* remove */
  assert(0==remove_comm_set_member(ctab, comm_set_1, 1));
  assert(2==tr_comm_table_size(ctab));
  assert(1==remove_comm_set_member(ctab, comm_set_1, 1)); /* should not be in the table */
  assert(2==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 2));
  assert(1==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 0));
  assert(0==tr_comm_table_size(ctab));
  
  /* add communities */
  assert(ctab!=NULL);
  assert(0==add_comm_set(ctab, comm_set_1));
  assert(3==tr_comm_table_size(ctab));
  assert(0==verify_comm_set(ctab, comm_set_1));

  /* remove */
  assert(0==remove_comm_set_member(ctab, comm_set_1, 2));
  assert(2==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 0));
  assert(1==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 1));
  assert(0==tr_comm_table_size(ctab));
  assert(1==remove_comm_set_member(ctab, comm_set_1, 1)); /* should not be in the table */
  assert(0==tr_comm_table_size(ctab));
  
  /* add communities */
  assert(ctab!=NULL);
  assert(0==add_comm_set(ctab, comm_set_1));
  assert(3==tr_comm_table_size(ctab));
  assert(0==verify_comm_set(ctab, comm_set_1));

  /* remove */
  assert(0==remove_comm_set_member(ctab, comm_set_1, 2));
  assert(2==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 1));
  assert(1==tr_comm_table_size(ctab));
  assert(1==remove_comm_set_member(ctab, comm_set_1, 1)); /* should not be in the table */
  assert(1==tr_comm_table_size(ctab));
  assert(0==remove_comm_set_member(ctab, comm_set_1, 0));
  assert(0==tr_comm_table_size(ctab));

  talloc_free(mem_ctx);
  return 0;
}

static int rp_realm_test(void)
{
  TALLOC_CTX *mem_ctx=talloc_new(NULL);
  TR_COMM_TABLE *ctab=tr_comm_table_new(mem_ctx);

  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_rp_realm_set(ctab, rp_realm_set_1));
  assert(0==verify_rp_realm_set(ctab, rp_realm_set_1));

  /* remove */
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 0));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 2));
  
  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_rp_realm_set(ctab, rp_realm_set_1));
  assert(0==verify_rp_realm_set(ctab, rp_realm_set_1));

  /* remove */
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 0));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 2));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1));
  
  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_rp_realm_set(ctab, rp_realm_set_1));
  assert(0==verify_rp_realm_set(ctab, rp_realm_set_1));

  /* remove */
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 0));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 2));
  
  assert(1==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1)); /* should not be in the table */

  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_rp_realm_set(ctab, rp_realm_set_1));
  assert(0==verify_rp_realm_set(ctab, rp_realm_set_1));

  /* remove */
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1));
  assert(1==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1)); /* should not be in the table */
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 2));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 0));
  
  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_rp_realm_set(ctab, rp_realm_set_1));
  assert(0==verify_rp_realm_set(ctab, rp_realm_set_1));

  /* remove */
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 2));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 0));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1));
  assert(1==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1)); /* should not be in the table */
  
  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_rp_realm_set(ctab, rp_realm_set_1));
  assert(0==verify_rp_realm_set(ctab, rp_realm_set_1));

  /* remove */
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 2));
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1));
  assert(1==remove_rp_realm_set_member(ctab, rp_realm_set_1, 1)); /* should not be in the table */
  assert(0==remove_rp_realm_set_member(ctab, rp_realm_set_1, 0));

  talloc_free(mem_ctx);
  return 0;
}

static int idp_realm_test(void)
{
  TALLOC_CTX *mem_ctx=talloc_new(NULL);
  TR_COMM_TABLE *ctab=tr_comm_table_new(mem_ctx);

  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_idp_realm_set(ctab, idp_realm_set_1));
  assert(0==verify_idp_realm_set(ctab, idp_realm_set_1));

  /* remove */
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 0));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 2));
  
  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_idp_realm_set(ctab, idp_realm_set_1));
  assert(0==verify_idp_realm_set(ctab, idp_realm_set_1));

  /* remove */
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 0));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 2));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1));
  
  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_idp_realm_set(ctab, idp_realm_set_1));
  assert(0==verify_idp_realm_set(ctab, idp_realm_set_1));

  /* remove */
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 0));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 2));
  
  assert(1==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1)); /* should not be in the table */

  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_idp_realm_set(ctab, idp_realm_set_1));
  assert(0==verify_idp_realm_set(ctab, idp_realm_set_1));

  /* remove */
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1));
  assert(1==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1)); /* should not be in the table */
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 2));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 0));
  
  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_idp_realm_set(ctab, idp_realm_set_1));
  assert(0==verify_idp_realm_set(ctab, idp_realm_set_1));

  /* remove */
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 2));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 0));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1));
  assert(1==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1)); /* should not be in the table */
  
  /* add realms */
  assert(ctab!=NULL);
  assert(0==add_idp_realm_set(ctab, idp_realm_set_1));
  assert(0==verify_idp_realm_set(ctab, idp_realm_set_1));

  /* remove */
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 2));
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1));
  assert(1==remove_idp_realm_set_member(ctab, idp_realm_set_1, 1)); /* should not be in the table */
  assert(0==remove_idp_realm_set_member(ctab, idp_realm_set_1, 0));

  talloc_free(mem_ctx);
  return 0;
}

static int membership_test(void)
{
  TALLOC_CTX *mem_ctx=talloc_new(NULL);
  TR_COMM_TABLE *ctab=tr_comm_table_new(mem_ctx);
  size_t ii=0;
  size_t size=0;

  assert(ctab!=NULL);
  assert(0==add_comm_set(ctab, comm_set_1));
  assert(0==add_rp_realm_set(ctab, rp_realm_set_1));
  assert(0==add_idp_realm_set(ctab, idp_realm_set_1));
  assert(0==add_member_set(ctab, member_set_1));

  size=tr_comm_table_size(ctab);
  tr_comm_table_sweep(ctab);
  assert(size==tr_comm_table_size(ctab));

  /* now remove memberships */
  for (ii=0; member_set_1[ii].role!=TR_ROLE_UNKNOWN; ii++) {
    assert(0==remove_membership(ctab, member_set_1, ii));
    assert(2==remove_membership(ctab, member_set_1, ii)); /* should not be in the table */
  }

  assert(NULL==ctab->memberships);

  /* put them back */
  assert(0==add_member_set(ctab, member_set_1));
  /* tr_comm_table_print(stdout, ctab); */

  tr_comm_table_sweep(ctab);
  assert(size==tr_comm_table_size(ctab));

  /* remove in the reverse order */
  for(; ii>0; ii--) {
    assert(0==remove_membership(ctab, member_set_1, ii-1));
    assert(2==remove_membership(ctab, member_set_1, ii-1)); /* should not be in the table */
    /* tr_comm_table_print(stdout, ctab); */
  }

  assert(NULL==ctab->memberships);

  assert(size==tr_comm_table_size(ctab));
  tr_comm_table_sweep(ctab);
  assert(0==tr_comm_table_size(ctab));

  talloc_free(mem_ctx);
  return 0;
}


/**********************************************************************/
/* main */
int main(void)
{
  assert(0==community_test());
  printf("Community tests passed.\n");
  assert(0==rp_realm_test());
  printf("RP realm tests passed.\n");
  assert(0==idp_realm_test());
  printf("IDP realm tests passed.\n");
  assert(0==membership_test());
  printf("Membership tests passed.\n");
  return 0;
}
