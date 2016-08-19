/* test suite for tr_config.c */
#include <stdio.h>
#include <talloc.h>
#include <assert.h>

#include <trust_router/tr_name.h>
#include <tr_comm.h>
#include <tr_idp.h>
#include <tr_config.h>
#include <tr_debug.h>

static void tr_talloc_log(const char *msg)
{
  tr_debug("talloc: %s", msg);
}

static int verify_idp_cfg(TR_CFG *cfg)
{
  TR_COMM *comm=NULL;
  TR_NAME *name=NULL;
  TR_APC *apc=NULL;
  TR_IDP_REALM *idp_realm=NULL;
  TR_AAA_SERVER *aaa=NULL;

  assert(cfg!=NULL);

  /* test the comms attribute */
  assert(cfg->comms!=NULL);
  name=tr_new_name("apc.example.com");
  comm=tr_comm_lookup(cfg->comms, name);
  tr_free_name(name);
  assert(comm!=NULL);

  assert(comm->type==TR_COMM_APC);
  assert(comm->expiration_interval==TR_DEFAULT_APC_EXPIRATION_INTERVAL);
  assert(comm->apcs==NULL);

  name=tr_new_name("A.idp.cfg");
  for (idp_realm=comm->idp_realms;
       (idp_realm!=NULL) && (tr_name_cmp(name, idp_realm->realm_id)!=0);
       idp_realm=idp_realm->comm_next) { }
  assert(idp_realm!=NULL);
  assert(idp_realm->shared_config==0);
  assert(idp_realm->origin==TR_REALM_LOCAL);
  tr_free_name(name);
  name=tr_new_name("apc.example.com");
  assert(tr_name_cmp(idp_realm->apcs->id, name)==0);
  tr_free_name(name);
  
  assert(idp_realm->aaa_servers!=NULL);
  name=tr_new_name("rad1.A.idp.cfg");
  for (aaa=idp_realm->aaa_servers;
       (aaa!=NULL) && (tr_name_cmp(name, aaa->hostname)!=0);
       aaa=aaa->next) { }
  assert(aaa!=NULL);
  tr_free_name(name);

  name=tr_new_name("rad2.A.idp.cfg");
  for (aaa=idp_realm->aaa_servers;
       (aaa!=NULL) && (tr_name_cmp(name, aaa->hostname)!=0);
       aaa=aaa->next) { }
  assert(aaa!=NULL);
  tr_free_name(name);

  return 0;
}

static int verify_rp_cfg(TR_CFG *cfg)
{
  int ii=0;
  TR_NAME *name=NULL;

  assert(cfg!=NULL);
  assert(cfg->rp_clients!=NULL);
  assert(cfg->rp_clients->next==NULL);
  assert(cfg->rp_clients->comm_next==NULL);
  for (ii=1; ii<TR_MAX_GSS_NAMES; ii++)
    assert(cfg->rp_clients->gss_names[ii]==NULL);
  assert(cfg->rp_clients->gss_names[0]!=NULL);
  name=tr_new_name("gss@example.com");
  assert(tr_name_cmp(name, cfg->rp_clients->gss_names[0])==0);
  return 0;
}

int main(void)
{
  TALLOC_CTX *mem_ctx=talloc_new(NULL);
  TR_CFG *cfg=NULL;
  TR_CFG_RC rc=TR_CFG_ERROR;

  tr_log_open();

  talloc_set_log_fn(tr_talloc_log);
  cfg=tr_cfg_new(mem_ctx);

  printf("Parsing idp.cfg.\n");
  rc=tr_cfg_parse_one_config_file(cfg, "idp.cfg");
  switch(rc) {
  case TR_CFG_SUCCESS:
    tr_debug("main: TR_CFG_SUCCESS");
    break;
  case TR_CFG_ERROR:
    tr_debug("main: TR_CFG_ERROR");
    break;
  case TR_CFG_BAD_PARAMS:
    tr_debug("main: TR_CFG_BAD_PARAMS");
    break;
  case TR_CFG_NOPARSE:
    tr_debug("main: TR_CFG_NOPARSE");
    break;
  case TR_CFG_NOMEM:
    tr_debug("main: TR_CFG_NOMEM");
    break;
  }

  printf("Verifying IDP parse results... ");
  if (verify_idp_cfg(cfg)!=0) {
    printf("Error!\n");
    exit(-1);
  }
  printf("success!\n");

  printf("Verifying RP parse results... ");
  if (verify_rp_cfg(cfg)!=0) {
    printf("Error!\n");
    exit(-1);
  }
  printf("success!\n");

  talloc_report_full(mem_ctx, stderr);
  tr_cfg_free(cfg);

  printf("Cleared configuration for next test.\n\n");

  cfg=tr_cfg_new(mem_ctx);
  
  printf("Parsing rp.cfg.\n");
  rc=tr_cfg_parse_one_config_file(cfg, "rp.cfg");
  switch(rc) {
  case TR_CFG_SUCCESS:
    tr_debug("main: TR_CFG_SUCCESS");
    break;
  case TR_CFG_ERROR:
    tr_debug("main: TR_CFG_ERROR");
    break;
  case TR_CFG_BAD_PARAMS:
    tr_debug("main: TR_CFG_BAD_PARAMS");
    break;
  case TR_CFG_NOPARSE:
    tr_debug("main: TR_CFG_NOPARSE");
    break;
  case TR_CFG_NOMEM:
    tr_debug("main: TR_CFG_NOMEM");
    break;
  }

#if 0
  printf("Verifying RP parse results... ");
  if (verify_rp_cfg(cfg)!=0) {
    printf("Error!\n");
    exit(-1);
  }
  printf("success!\n");
#endif

  talloc_free(mem_ctx);
  return 0;
}
