#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <assert.h>

#include <tr_filter.h>
#include <trp_internal.h>
#include <tid_internal.h>
#include <tr_inet_util.h>
#include <tr_debug.h>

/**
 * Create a filter target for a TRP inforec. Does not change the context of the inforec or duplicate TR_NAMEs,
 * so this is only valid until those are freed.
 *
 * @param mem_ctx talloc context for the object
 * @param upd Update containing the TRP inforec
 * @param inforec TRP inforec
 * @return pointer to a TR_FILTER_TARGET structure, or null on allocation failure
 */
TR_FILTER_TARGET *tr_filter_target_trp_inforec(TALLOC_CTX *mem_ctx, TRP_UPD *upd, TRP_INFOREC *inforec)
{
  TR_FILTER_TARGET *target=tr_filter_target_new(mem_ctx);
  if (target) {
    target->trp_inforec = inforec; /* borrowed, not adding to our context */
    target->trp_upd=upd;
  }
  return target;
}

/** Handler functions for TRP info_type field */
static int tr_ff_cmp_trp_info_type(TR_FILTER_TARGET *target, TR_NAME *val)
{
  TRP_INFOREC *inforec=target->trp_inforec;
  char *valstr=NULL;
  int val_type=0;

  assert(val);
  assert(inforec);

  /* nothing matches unknown */
  if (inforec->type==TRP_INFOREC_TYPE_UNKNOWN)
    return 0;

  valstr = tr_name_strdup(val); /* get this as an official null-terminated string */
  val_type = trp_inforec_type_from_string(valstr);
  free(valstr);

  /* we do not define an ordering of info types */
  return (val_type==inforec->type);
}

static TR_NAME *tr_ff_get_trp_info_type(TR_FILTER_TARGET *target)
{
  TRP_INFOREC *inforec=target->trp_inforec;
  return tr_new_name(trp_inforec_type_to_string(inforec->type));
}

/** Handlers for TRP realm field */
static int tr_ff_cmp_trp_realm(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_name_cmp(trp_upd_get_realm(target->trp_upd), val);
}

static TR_NAME *tr_ff_get_trp_realm(TR_FILTER_TARGET *target)
{
  return tr_dup_name(trp_upd_get_realm(target->trp_upd));
}

/** Handlers for TRP community field */
static int tr_ff_cmp_trp_comm(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_name_cmp(trp_upd_get_comm(target->trp_upd), val);
}

static TR_NAME *tr_ff_get_trp_comm(TR_FILTER_TARGET *target)
{
  return tr_dup_name(trp_upd_get_comm(target->trp_upd));
}

/** Handlers for TRP community_type field */
static TR_NAME *tr_ff_get_trp_comm_type(TR_FILTER_TARGET *target)
{
  TR_NAME *type=NULL;

  switch(trp_inforec_get_comm_type(target->trp_inforec)) {
    case TR_COMM_APC:
      type=tr_new_name("apc");
      break;
    case TR_COMM_COI:
      type=tr_new_name("coi");
      break;
    default:
      type=NULL;
      break; /* unknown types always fail */
  }

  return type;
}

static int tr_ff_cmp_trp_comm_type(TR_FILTER_TARGET *target, TR_NAME *val)
{
  TR_NAME *type=tr_ff_get_trp_comm_type(target);
  int retval=0;

  if (type==NULL)
    retval=1;
  else {
    retval = tr_name_cmp(val, type);
    tr_free_name(type);
  }
  return retval;
}

/** Handlers for TRP realm_role field */
static TR_NAME *tr_ff_get_trp_realm_role(TR_FILTER_TARGET *target)
{
  TR_NAME *type=NULL;

  switch(trp_inforec_get_role(target->trp_inforec)) {
    case TR_ROLE_IDP:
      type=tr_new_name("idp");
      break;
    case TR_ROLE_RP:
      type=tr_new_name("rp");
      break;
    default:
      type=NULL;
      break; /* unknown types always fail */
  }

  return type;
}

static int tr_ff_cmp_trp_realm_role(TR_FILTER_TARGET *target, TR_NAME *val)
{
  TR_NAME *type=tr_ff_get_trp_realm_role(target);
  int retval=0;

  if (type==NULL)
    retval=1;
  else {
    retval = tr_name_cmp(val, type);
    tr_free_name(type);
  }
  return retval;
}

/** Handlers for TRP apc field */
/* TODO: Handle multiple APCs, not just the first */
static int tr_ff_cmp_trp_apc(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_name_cmp(tr_apc_get_id(trp_inforec_get_apcs(target->trp_inforec)), val);
}

static TR_NAME *tr_ff_get_trp_apc(TR_FILTER_TARGET *target)
{
  TR_APC *apc=trp_inforec_get_apcs(target->trp_inforec);
  if (apc==NULL)
    return NULL;

  return tr_dup_name(tr_apc_get_id(apc));
}

/** Handlers for TRP owner_realm field */
static int tr_ff_cmp_trp_owner_realm(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_name_cmp(trp_inforec_get_owner_realm(target->trp_inforec), val);
}

static TR_NAME *tr_ff_get_trp_owner_realm(TR_FILTER_TARGET *target)
{
  return tr_dup_name(trp_inforec_get_owner_realm(target->trp_inforec));
}

/** Generic handlers for host:port fields*/
static TR_NAME *tr_ff_get_hostname_and_port(TR_NAME *hn, int port)
{
  return tr_hostname_and_port_to_name(hn, port);
}

static int tr_ff_cmp_hostname_and_port(TR_NAME *hn, int port, int default_port, TR_NAME *val)
{
  int cmp = -1;
  TR_NAME *n = NULL;

  /* allow a match without :port if the default port is in use */
  if ((port == default_port) && (tr_name_cmp(hn, val) == 0))
    return 0;

  /* need to match with the :port */
  n = tr_ff_get_hostname_and_port(hn, port);

  if (n) {
    cmp = tr_name_cmp(n, val);
    tr_free_name(n);
  }
  return cmp;
}

/** Handlers for TRP trust_router field */
static int tr_ff_cmp_trp_trust_router(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_ff_cmp_hostname_and_port(trp_inforec_get_trust_router(target->trp_inforec),
                                     trp_inforec_get_trust_router_port(target->trp_inforec),
                                     TRP_PORT,
                                     val);
}

static TR_NAME *tr_ff_get_trp_trust_router(TR_FILTER_TARGET *target)
{
  return tr_ff_get_hostname_and_port(trp_inforec_get_trust_router(target->trp_inforec),
                                     trp_inforec_get_trust_router_port(target->trp_inforec));
}

/** Handlers for TRP next_hop field */
static int tr_ff_cmp_trp_next_hop(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_ff_cmp_hostname_and_port(trp_inforec_get_next_hop(target->trp_inforec),
                                     trp_inforec_get_next_hop_port(target->trp_inforec),
                                     TID_PORT,
                                     val);
}

static TR_NAME *tr_ff_get_trp_next_hop(TR_FILTER_TARGET *target)
{
  return tr_ff_get_hostname_and_port(trp_inforec_get_next_hop(target->trp_inforec),
                                     trp_inforec_get_next_hop_port(target->trp_inforec));
}

/** Handlers for TRP owner_contact field */
static int tr_ff_cmp_trp_owner_contact(TR_FILTER_TARGET *target, TR_NAME *val)
{
  return tr_name_cmp(trp_inforec_get_owner_contact(target->trp_inforec), val);
}

static TR_NAME *tr_ff_get_trp_owner_contact(TR_FILTER_TARGET *target)
{
  return tr_dup_name(trp_inforec_get_owner_contact(target->trp_inforec));
}

void trp_filter_init(void)
{
  /* realm */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "realm", tr_ff_cmp_trp_realm, tr_ff_get_trp_realm);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "realm", tr_ff_cmp_trp_realm, tr_ff_get_trp_realm);

  /* community */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "comm", tr_ff_cmp_trp_comm, tr_ff_get_trp_comm);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "comm", tr_ff_cmp_trp_comm, tr_ff_get_trp_comm);

  /* community type */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "comm_type", tr_ff_cmp_trp_comm_type, tr_ff_get_trp_comm_type);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "comm_type", tr_ff_cmp_trp_comm_type, tr_ff_get_trp_comm_type);

  /* realm role */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "realm_role", tr_ff_cmp_trp_realm_role, tr_ff_get_trp_realm_role);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "realm_role", tr_ff_cmp_trp_realm_role, tr_ff_get_trp_realm_role);

  /* apc */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "apc", tr_ff_cmp_trp_apc, tr_ff_get_trp_apc);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "apc", tr_ff_cmp_trp_apc, tr_ff_get_trp_apc);

  /* trust_router */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "trust_router", tr_ff_cmp_trp_trust_router, tr_ff_get_trp_trust_router);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "trust_router", tr_ff_cmp_trp_trust_router, tr_ff_get_trp_trust_router);

  /* next_hop */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "next_hop", tr_ff_cmp_trp_next_hop, tr_ff_get_trp_next_hop);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "next_hop", tr_ff_cmp_trp_next_hop, tr_ff_get_trp_next_hop);

  /* owner_realm */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "owner_realm", tr_ff_cmp_trp_owner_realm, tr_ff_get_trp_owner_realm);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "owner_realm", tr_ff_cmp_trp_owner_realm, tr_ff_get_trp_owner_realm);

  /* owner_contact */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "owner_contact", tr_ff_cmp_trp_owner_contact, tr_ff_get_trp_owner_contact);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "owner_contact", tr_ff_cmp_trp_owner_contact, tr_ff_get_trp_owner_contact);

  /* info_type */
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_INBOUND, "info_type", tr_ff_cmp_trp_info_type, tr_ff_get_trp_info_type);
  tr_filter_add_field_handler(TR_FILTER_TYPE_TRP_OUTBOUND, "info_type", tr_ff_cmp_trp_info_type, tr_ff_get_trp_info_type);
}
