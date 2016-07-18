#include <jansson.h>
#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <tr_debug.h>


/* static prototypes */
static void *trp_inforec_route_new(TALLOC_CTX *mem_ctx);
static void trp_inforec_route_print(TRP_INFOREC_DATA);


struct trp_inforec_type_entry {
  const char *name;
  TRP_INFOREC_TYPE type;
  void *(*allocate)(TALLOC_CTX *);
  void (*print)(TRP_INFOREC_DATA);
};
static struct trp_inforec_type_entry trp_inforec_type_table[] = {
  { "route", TRP_INFOREC_TYPE_ROUTE, trp_inforec_route_new, trp_inforec_route_print },
  { "comm", TRP_INFOREC_TYPE_COMMUNITY, NULL, NULL },
  { NULL, TRP_INFOREC_TYPE_UNKNOWN, NULL, NULL } /* must be the last entry */
};


/* look up an entry in the trp_inforec_type_table */
static struct trp_inforec_type_entry *get_trp_inforec_type_entry(TRP_INFOREC_TYPE msgtype)
{
  struct trp_inforec_type_entry *entry=trp_inforec_type_table;

  while ((entry->type != TRP_INFOREC_TYPE_UNKNOWN)
        && (entry->type != msgtype)) {
    entry ++;
  }
  return entry;
}

/* translate strings to codes */
TRP_INFOREC_TYPE trp_inforec_type_from_string(const char *s)
{
  struct trp_inforec_type_entry *entry=trp_inforec_type_table;

  while ((entry->type != TRP_INFOREC_TYPE_UNKNOWN)
        && (strcmp(s, entry->name)!=0)) {
    entry++;
  }
  return entry->type;
}
/* translate codes to strings (do not need to be freed) 
 * Returns NULL on an unknown code */
const char *trp_inforec_type_to_string(TRP_INFOREC_TYPE msgtype)
{
  struct trp_inforec_type_entry *entry=get_trp_inforec_type_entry(msgtype);
  return entry->name;
}

/* called by talloc when destroying an update message body */
static int trp_inforec_route_destructor(void *object)
{
  TRP_INFOREC_ROUTE *body=talloc_get_type_abort(object, TRP_INFOREC_ROUTE);
  
  /* clean up TR_NAME data, which are not managed by talloc */
  if (body->comm != NULL) {
    tr_free_name(body->comm);
    body->comm=NULL;
    tr_debug("trp_inforec_route_destructor: freed community");
  }
  if (body->realm != NULL) {
    tr_free_name(body->realm);
    body->realm=NULL;
    tr_debug("trp_inforec_route_destructor: freed realm");
  }
  if (body->trust_router != NULL) {
    tr_free_name(body->trust_router);
    body->trust_router=NULL;
    tr_debug("trp_inforec_route_destructor: freed trust_router");
  }
  if (body->next_hop != NULL) {
    tr_free_name(body->next_hop);
    body->next_hop=NULL;
    tr_debug("trp_inforec_route_destructor: freed next_hop");
  }

  return 0;
}

static void *trp_inforec_route_new(TALLOC_CTX *mem_ctx)
{
  TRP_INFOREC_ROUTE *new_rec=talloc(mem_ctx, TRP_INFOREC_ROUTE);

  if (new_rec != NULL) {
    new_rec->comm=NULL;
    new_rec->realm=NULL;
    new_rec->trust_router=NULL;
    new_rec->next_hop=NULL;
    new_rec->metric=TRP_METRIC_INFINITY;
    new_rec->interval=0;
    talloc_set_destructor((void *)new_rec, trp_inforec_route_destructor);
  }
  return new_rec;
}

TRP_INFOREC *trp_inforec_get_next(TRP_INFOREC *rec)
{
  if (rec!=NULL)
    return rec->next;
  else
    return NULL;
}

static TRP_INFOREC *trp_inforec_get_tail(TRP_INFOREC *rec)
{
  while (rec!=NULL)
    rec=trp_inforec_get_next(rec);
  return rec;
}

void trp_inforec_set_next(TRP_INFOREC *rec, TRP_INFOREC *next_rec)
{
  if (rec !=NULL)
    rec->next=next_rec;
}

TRP_INFOREC_TYPE trp_inforec_get_type(TRP_INFOREC *rec)
{
  if (rec)
    return rec->type;
  else
    return TRP_INFOREC_TYPE_UNKNOWN;
}

void trp_inforec_set_type(TRP_INFOREC *rec, TRP_INFOREC_TYPE type)
{
  if (rec!=NULL)
    rec->type=type;
}

TR_NAME *trp_inforec_get_comm(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL)
      return rec->data.route->comm;
    break;
  default:
    break;
  }
  return NULL;
}

TRP_RC trp_inforec_set_comm(TRP_INFOREC *rec, TR_NAME *comm)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL) {
      rec->data.route->comm=comm;
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

TR_NAME *trp_inforec_get_realm(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL)
      return rec->data.route->realm;
    break;
  default:
    break;
  }
  return NULL;
}

TRP_RC trp_inforec_set_realm(TRP_INFOREC *rec, TR_NAME *realm)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL) {
      rec->data.route->realm=realm;
      return TRP_SUCCESS;
    } 
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

TR_NAME *trp_inforec_get_trust_router(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL)
      return rec->data.route->trust_router;
    break;
  default:
    break;
  }
  return NULL;
}

TRP_RC trp_inforec_set_trust_router(TRP_INFOREC *rec, TR_NAME *trust_router)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL) {
      rec->data.route->trust_router=trust_router;
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

TR_NAME *trp_inforec_get_next_hop(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL)
      return rec->data.route->next_hop;
    break;
  default:
    break;
  }
  return NULL;
}

TRP_RC trp_inforec_set_next_hop(TRP_INFOREC *rec, TR_NAME *next_hop)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL) {
      rec->data.route->next_hop=next_hop;
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

unsigned int trp_inforec_get_metric(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL)
      return rec->data.route->metric;
    break;
  default:
    break;
  }
  return TRP_METRIC_INVALID;
}

TRP_RC trp_inforec_set_metric(TRP_INFOREC *rec, unsigned int metric)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL) {
      rec->data.route->metric=metric;
      return TRP_SUCCESS;
    }
    break;
  default:
    break;
  }
  return TRP_ERROR;
}

unsigned int trp_inforec_get_interval(TRP_INFOREC *rec)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL)
      return rec->data.route->interval;
    break;
  default:
    break;
  }
  return TRP_INTERVAL_INVALID;
}

TRP_RC trp_inforec_set_interval(TRP_INFOREC *rec, unsigned int interval)
{
  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    if (rec->data.route!=NULL) {
      rec->data.route->interval=interval;
      return TRP_SUCCESS;
  default:
    break;
    }
    break;
  }
  return TRP_ERROR;
}

/* for internal use only; must set rec->type before calling this */
static TRP_RC trp_inforec_set_data(TRP_INFOREC *rec, void *data)
{
  if (data==NULL)
    return TRP_ERROR;

  switch (rec->type) {
  case TRP_INFOREC_TYPE_ROUTE:
    rec->data.route=talloc_get_type(data, TRP_INFOREC_ROUTE);
    break;
  default:
    return TRP_BADTYPE;
  }
  return TRP_SUCCESS;
}

/* generic record type */
TRP_INFOREC *trp_inforec_new(TALLOC_CTX *mem_ctx, TRP_INFOREC_TYPE type)
{
  TRP_INFOREC *new_rec=talloc(mem_ctx, TRP_INFOREC);
  struct trp_inforec_type_entry *dtype=get_trp_inforec_type_entry(type);

  if ((new_rec != NULL) && (dtype->type != TRP_INFOREC_TYPE_UNKNOWN)) {
    trp_inforec_set_type(new_rec, type);
    trp_inforec_set_next(new_rec, NULL);
    if (dtype->allocate!=NULL) {
      if (TRP_SUCCESS!=trp_inforec_set_data(new_rec, dtype->allocate(new_rec))) {
        talloc_free(new_rec);
        new_rec=NULL;
      }
    }
  }
  return new_rec;
}

void trp_inforec_free(TRP_INFOREC *rec)
{
  if (rec!=NULL)
    talloc_free(rec);
}

static int trp_upd_destructor(void *object)
{
  TRP_UPD *upd=talloc_get_type_abort(object, TRP_UPD);
  if (upd->peer!=NULL)
    tr_free_name(upd->peer);
  return 0;
}

TRP_UPD *trp_upd_new(TALLOC_CTX *mem_ctx)
{
  TRP_UPD *new_body=talloc(mem_ctx, TRP_UPD);

  if (new_body!=NULL) {
    new_body->records=NULL;
    new_body->peer=NULL;
    talloc_set_destructor((void *)new_body, trp_upd_destructor);
  }
  return new_body;
}

void trp_upd_free(TRP_UPD *update)
{
  if (update!=NULL)
    talloc_free(update);
}

TRP_INFOREC *trp_upd_get_inforec(TRP_UPD *upd)
{
  if (upd!=NULL)
    return upd->records;
  else
    return NULL;
}

void trp_upd_set_inforec(TRP_UPD *upd, TRP_INFOREC *rec)
{
  if (upd!=NULL)
    upd->records=rec;
}

void trp_upd_add_inforec(TRP_UPD *upd, TRP_INFOREC *rec)
{
  if (upd->records==NULL)
    upd->records=rec;
  else
    trp_inforec_set_next(trp_inforec_get_tail(upd->records), rec);
  talloc_steal(upd, rec);
}

TR_NAME *trp_upd_get_peer(TRP_UPD *upd)
{
  return upd->peer;
}

void trp_upd_set_peer(TRP_UPD *upd, TR_NAME *peer)
{
  TRP_INFOREC *rec=NULL;
  TR_NAME *cpy=NULL;

  upd->peer=peer;
  for (rec=trp_upd_get_inforec(upd); rec!=NULL; rec=trp_inforec_get_next(rec)) {
    if (trp_inforec_set_next_hop(rec, cpy=tr_dup_name(peer)) != TRP_SUCCESS) {
      tr_err("trp_upd_set_peer: error setting peer.");
      tr_free_name(cpy);
    }
  }
}

/* pretty print */
static void trp_inforec_route_print(TRP_INFOREC_DATA data)
{
  if (data.route!=NULL) {
    printf("     community=%.*s\n     realm=%.*s\n     trust_router=%.*s\n     metric=%d\n     interval=%d]\n",
           data.route->comm->len, data.route->comm->buf,
           data.route->realm->len, data.route->realm->buf,
           data.route->trust_router->len, data.route->trust_router->buf,
           data.route->metric, data.route->interval);
  }
}

