#include <jansson.h>
#include <talloc.h>

#include <tr_name.h>
#include <trp_internal.h>
#include <tr_debug.h>


/* static prototypes */
static void *trp_route_update_new(TALLOC_CTX *mem_ctx);
static TRP_RC trp_parse_update(TRP_MSG *msg, json_t *jmsg);
static void trp_route_update_print(void *);

static void *trp_route_req_new(TALLOC_CTX *mem_ctx);
static json_t *trp_encode_route_req(void *req_in);
static TRP_RC trp_parse_route_req(TRP_MSG *msg, json_t *jmsg);
static void trp_route_req_print(void *);

static void *trp_msg_info_route_new(TALLOC_CTX *mem_ctx);
static TRP_RC trp_encode_info_route(json_t *jrec, void *route_in);
static TRP_RC trp_parse_info_route(TRP_MSG *msg, json_t *jmsg);
static void trp_msg_info_route_print(void *);

/* table of string names for TMT_MSG_TYPE codes */
struct trp_msg_type_entry {
  const char *name;
  TRP_MSG_TYPE type;
  void *(*allocate)(TALLOC_CTX *);
  json_t *(*encode)(void *);
  TRP_RC (*parse)(TRP_MSG *, json_t *);
  void (*print)(void *);
};
static struct trp_msg_type_entry trp_msg_type_table[] = {
  { "update", TRP_MSG_TYPE_UPDATE, trp_route_update_new, NULL, trp_parse_update, trp_route_update_print },
  { "route_req", TRP_MSG_TYPE_ROUTE_REQ, trp_route_req_new, trp_encode_route_req, trp_parse_route_req, trp_route_req_print },
  { NULL, TRP_MSG_TYPE_UNKNOWN, NULL, NULL, NULL, NULL } /* must be the last entry */
};

struct trp_msg_info_type_entry {
  const char *name;
  TRP_MSG_INFO_TYPE type;
  void *(*allocate)(TALLOC_CTX *);
  TRP_RC (*encode)(json_t *, void *);
  void (*print)(void *);
};
static struct trp_msg_info_type_entry trp_msg_info_type_table[] = {
  { "route_info", TRP_MSG_INFO_TYPE_ROUTE, trp_msg_info_route_new, trp_encode_info_route, trp_msg_info_route_print },
  { "comm_info", TRP_MSG_INFO_TYPE_COMMUNITY, NULL, NULL, NULL },
  { NULL, TRP_MSG_INFO_TYPE_UNKNOWN, NULL, NULL, NULL } /* must be the last entry */
};

/* Use talloc's dynamic type checking to verify type.
 * By default, this will cause program abort, but can be overridden
 * via talloc_set_abort_fn() if more graceful handling is needed. */
static void msg_body_type_check(TRP_MSG_TYPE msgtype, void *p)
{
  switch (msgtype) {
  case TRP_MSG_TYPE_UPDATE:
    talloc_get_type_abort(p, TRP_ROUTE_UPDATE);
    break;

  case TRP_MSG_TYPE_ROUTE_REQ:
    talloc_get_type_abort(p, TRP_ROUTE_REQ);
    break;

  default:
    break;
  }
}

/* look up an entry in the trp_msg_type_table */
static struct trp_msg_type_entry *get_trp_msg_type_entry(TRP_MSG_TYPE msgtype)
{
  struct trp_msg_type_entry *entry=trp_msg_type_table;

  while ((entry->type != TRP_MSG_TYPE_UNKNOWN)
        && (entry->type != msgtype)) {
    entry ++;
  }
  return entry;
}

/* look up an entry in the trp_msg_info_type_table */
static struct trp_msg_info_type_entry *get_trp_msg_info_type_entry(TRP_MSG_INFO_TYPE msgtype)
{
  struct trp_msg_info_type_entry *entry=trp_msg_info_type_table;

  while ((entry->type != TRP_MSG_INFO_TYPE_UNKNOWN)
        && (entry->type != msgtype)) {
    entry ++;
  }
  return entry;
}

/* translate strings to codes */
TRP_MSG_TYPE trp_msg_type_from_string(const char *s)
{
  struct trp_msg_type_entry *entry=trp_msg_type_table;

  while ((entry->type != TRP_MSG_TYPE_UNKNOWN)
        && (strcmp(s, entry->name)!=0)) {
    entry++;
  }
  return entry->type;
}
/* translate codes to strings (do not need to be freed) 
 * Returns NULL on an unknown code */
const char *trp_msg_type_to_string(TRP_MSG_TYPE msgtype)
{
  struct trp_msg_type_entry *entry=get_trp_msg_type_entry(msgtype);
  return entry->name;
}

/* translate strings to codes */
TRP_MSG_INFO_TYPE trp_msg_info_type_from_string(const char *s)
{
  struct trp_msg_info_type_entry *entry=trp_msg_info_type_table;

  while ((entry->type != TRP_MSG_INFO_TYPE_UNKNOWN)
        && (strcmp(s, entry->name)!=0)) {
    entry++;
  }
  return entry->type;
}
/* translate codes to strings (do not need to be freed) 
 * Returns NULL on an unknown code */
const char *trp_msg_info_type_to_string(TRP_MSG_INFO_TYPE msgtype)
{
  struct trp_msg_info_type_entry *entry=get_trp_msg_info_type_entry(msgtype);
  return entry->name;
}


TRP_MSG *trp_msg_new(TALLOC_CTX *mem_ctx)
{
  TRP_MSG *new_msg=talloc(mem_ctx, TRP_MSG);

  if (new_msg != NULL) {
    new_msg->type=TRP_MSG_INFO_TYPE_UNKNOWN;
    new_msg->body=NULL;
  }
  return new_msg;
}

void trp_msg_destroy(TRP_MSG *msg)
{
  if (msg)
    talloc_free(msg);
}


/* JSON helpers */
/* Read attribute attr from msg as an integer */
static TRP_RC trp_get_json_integer(json_t *jmsg, const char *attr, int *dest)
{
  json_error_t err;
  json_t *obj;

  obj=json_object_get(jmsg, attr);
  if (obj == NULL) {
    return TRP_NOPARSE;
  }
  /* check type */
  if (!json_is_integer(obj)) {
    return TRP_BADTYPE;
  }

  (*dest)=json_integer_value(obj);
  return TRP_SUCCESS;
}

/* Read attribute attr from msg as a string. Copies string into mem_ctx context so jmsg can
 * be destroyed safely. */
static TRP_RC trp_get_json_string(json_t *jmsg, const char *attr, char **dest, TALLOC_CTX *mem_ctx)
{
  json_error_t err;
  json_t *obj;

  obj=json_object_get(jmsg, attr);
  if (obj == NULL)
    return TRP_NOPARSE;

  /* check type */
  if (!json_is_string(obj))
    return TRP_BADTYPE;

  *dest=talloc_strdup(mem_ctx, json_string_value(obj));
  if (*dest==NULL)
    return TRP_NOMEM;

  return TRP_SUCCESS;
}


/* called by talloc when destroying an update message body */
static int trp_msg_info_route_destructor(void *object)
{
  TRP_MSG_INFO_ROUTE *body=talloc_get_type_abort(object, TRP_MSG_INFO_ROUTE);
  
  /* clean up TR_NAME data, which are not managed by talloc */
  if (body->comm != NULL) {
    tr_free_name(body->comm);
    body->comm=NULL;
    tr_debug("trp_msg_info_route_destructor: freed community");
  }
  if (body->realm != NULL) {
    tr_free_name(body->realm);
    body->realm=NULL;
    tr_debug("trp_msg_info_route_destructor: freed realm");
  }
  if (body->trust_router != NULL) {
    tr_free_name(body->trust_router);
    body->trust_router=NULL;
    tr_debug("trp_msg_info_route_destructor: freed trust_router");
  }

  return 0;
}

static void *trp_msg_info_route_new(TALLOC_CTX *mem_ctx)
{
  TRP_MSG_INFO_ROUTE *new_rec=talloc(mem_ctx, TRP_MSG_INFO_ROUTE);

  if (new_rec != NULL) {
    new_rec->comm=NULL;
    new_rec->realm=NULL;
    new_rec->trust_router=NULL;
    new_rec->metric=TRP_METRIC_INFINITY;
    new_rec->interval=0;
    talloc_set_destructor((void *)new_rec, trp_msg_info_route_destructor);
  }
  return new_rec;
}

TR_NAME *trp_msg_info_route_get_comm(TRP_MSG_INFO_REC *rec)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL))
    return route->comm;
  else
    return NULL;
}

TRP_RC trp_msg_info_route_set_comm(TRP_MSG_INFO_REC *rec, TR_NAME *comm)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL)) {
    route->comm=comm;
    return TRP_SUCCESS;
  } else
    return TRP_BADTYPE;
}

TR_NAME *trp_msg_info_route_get_realm(TRP_MSG_INFO_REC *rec)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL))
    return route->realm;
  else
    return NULL;
}

TRP_RC trp_msg_info_route_set_realm(TRP_MSG_INFO_REC *rec, TR_NAME *realm)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL)) {
    route->realm=realm;
    return TRP_SUCCESS;
  } else
    return TRP_BADTYPE;
}

TR_NAME *trp_msg_info_route_get_trust_router(TRP_MSG_INFO_REC *rec)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL))
    return route->trust_router;
  else
    return NULL;
}

TRP_RC trp_msg_info_route_set_trust_router(TRP_MSG_INFO_REC *rec, TR_NAME *trust_router)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL)) {
    route->trust_router=trust_router;
    return TRP_SUCCESS;
  } else
    return TRP_BADTYPE;
}

unsigned int trp_msg_info_route_get_metric(TRP_MSG_INFO_REC *rec)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL))
    return route->metric;
  else
    return TRP_METRIC_INVALID;
}

TRP_RC trp_msg_info_route_set_metric(TRP_MSG_INFO_REC *rec, unsigned int metric)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL)) {
    route->metric=metric;
    return TRP_SUCCESS;
  } else
    return TRP_BADTYPE;
}

unsigned int trp_msg_info_route_get_interval(TRP_MSG_INFO_REC *rec)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL))
    return route->interval;
  else
    return TRP_INTERVAL_INVALID;
}

TRP_RC trp_msg_info_route_set_interval(TRP_MSG_INFO_REC *rec, unsigned int interval)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(rec->data, TRP_MSG_INFO_ROUTE);
  if ((rec->type==TRP_MSG_INFO_TYPE_ROUTE) && (route!=NULL)) {
    route->interval=interval;
    return TRP_SUCCESS;
  } else
    return TRP_BADTYPE;
}

/* generic record type */
static void *trp_msg_info_rec_new(TALLOC_CTX *mem_ctx, TRP_MSG_INFO_TYPE type)
{
  TRP_MSG_INFO_REC *new_rec=talloc(mem_ctx, TRP_MSG_INFO_REC);
  struct trp_msg_info_type_entry *dtype=get_trp_msg_info_type_entry(type);

  if ((new_rec != NULL) && (dtype->type != TRP_MSG_INFO_TYPE_UNKNOWN)) {
    new_rec->next=NULL;
    new_rec->type=type;
    if (dtype->allocate!=NULL)
      new_rec->data=dtype->allocate(new_rec);
    if (new_rec->data==NULL) {
      /* dtype->allocate() failed or did not exist */
      talloc_free(new_rec); new_rec=NULL;
    }
  }
  return new_rec;
}

/* parse a single record */
static TRP_RC trp_parse_update_record(TALLOC_CTX *mem_ctx, TRP_MSG_INFO_REC **rec, json_t *jrecord)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_MSG_INFO_TYPE rectype;
  TRP_RC rc=TRP_ERROR;
  char *s=NULL;
  int num=0;
  
  rc=trp_get_json_string(jrecord, "record_type", &s, tmp_ctx);
  if (rc != TRP_SUCCESS)
    goto cleanup;
  rectype=trp_msg_info_type_from_string(s);
  talloc_free(s); s=NULL;

  (*rec)=trp_msg_info_rec_new(tmp_ctx, rectype);
  if ((*rec)==NULL) {
    rc=TRP_NOMEM;
    goto cleanup;
  }

  /* We only support route_info records for now*/
  if ((*rec)->type!=TRP_MSG_INFO_TYPE_ROUTE) {
    rc=TRP_UNSUPPORTED;
    goto cleanup;
  }

  tr_debug("trp_parse_update_record: '%s' record found.", trp_msg_info_type_to_string((*rec)->type));

  rc=trp_get_json_string(jrecord, "community", &s, tmp_ctx);
  if (rc != TRP_SUCCESS)
    goto cleanup;
  if (TRP_SUCCESS!=trp_msg_info_route_set_comm(*rec, tr_new_name(s))) /* assumes route_info */
    goto cleanup;
  talloc_free(s); s=NULL;

  rc=trp_get_json_string(jrecord, "realm", &s, tmp_ctx);
  if (rc != TRP_SUCCESS)
    goto cleanup;
  if (TRP_SUCCESS!=trp_msg_info_route_set_realm(*rec, tr_new_name(s))) /* assumes route_info */
    goto cleanup;
  talloc_free(s); s=NULL;

  rc=trp_get_json_string(jrecord, "trust_router", &s, tmp_ctx);
  if (rc != TRP_SUCCESS)
    goto cleanup;
  if (TRP_SUCCESS!=trp_msg_info_route_set_trust_router(*rec, tr_new_name(s))) /* assumes route_info */
    goto cleanup;
  talloc_free(s); s=NULL;

  rc=trp_get_json_integer(jrecord, "metric", &num);
  if ((rc != TRP_SUCCESS) || (TRP_SUCCESS!=trp_msg_info_route_set_metric(*rec,num)))
    goto cleanup;

  rc=trp_get_json_integer(jrecord, "interval", &num);
  if ((rc != TRP_SUCCESS) || (TRP_SUCCESS!=trp_msg_info_route_set_interval(*rec,num)))
    goto cleanup;

  talloc_steal(mem_ctx, *rec);
  rc=TRP_SUCCESS;

cleanup:
  if (rc != TRP_SUCCESS) {
    /* kind of a hack, assumes we only have route_info records */
    trp_msg_info_route_destructor((*rec)->data);
    (*rec)=NULL;
  }
  talloc_free(tmp_ctx);
  return rc;
}

static void *trp_route_update_new(TALLOC_CTX *mem_ctx)
{
  TRP_ROUTE_UPDATE *new_body=talloc(mem_ctx, TRP_ROUTE_UPDATE);

  if (new_body!=NULL) {
    new_body->records=NULL;
  }
}

/* Parse an update body. Creates a linked list of records in the msg->body talloc context.
 *
 * An error will be returned if any unparseable records are encountered. 
 *
 * TODO: clean up return codes. 
 * TODO: should take a body, not a msg */
static TRP_RC trp_parse_update(TRP_MSG *msg, json_t *jbody)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  json_t *jrecords=NULL;
  size_t ii=0;
  size_t nrec=0;
  TRP_ROUTE_UPDATE *msg_body=NULL;
  TRP_MSG_INFO_REC *new_rec=NULL;
  TRP_MSG_INFO_REC *list_tail=NULL;
  TRP_RC rc=TRP_ERROR;

  if (msg->type != TRP_MSG_TYPE_UPDATE) {
    rc=TRP_BADTYPE;
    goto cleanup;
  }
  msg_body=talloc_get_type(msg->body, TRP_ROUTE_UPDATE);
  if (msg_body==NULL) {
    rc=TRP_BADTYPE;
    goto cleanup;
  }

  jrecords=json_object_get(jbody, "records");
  if ((jrecords==NULL) || (!json_is_array(jrecords))) {
    rc=TRP_NOPARSE;
    goto cleanup;
  }

  tr_debug("trp_parse_update: found %d records", json_array_size(jrecords));
  /* process the array */
  for (ii=0; ii<json_array_size(jrecords); ii++) {
    if (TRP_SUCCESS != trp_parse_update_record(tmp_ctx, &new_rec, json_array_get(jrecords, ii))) {
      rc=TRP_NOPARSE;
      goto cleanup;
    }

    printf("new_rec: %p\n", new_rec);
    if (list_tail==NULL)
      msg_body->records=new_rec; /* first is a special case */
    else
      list_tail->next=new_rec;

    list_tail=new_rec;
  }

  /* Succeeded. Move all of our new allocations into the correct talloc context */
  for (list_tail=msg_body->records; list_tail != NULL; list_tail=list_tail->next)
    talloc_steal(msg->body, list_tail); /* all successfully parsed bodies belong to msg context */

  rc=TRP_SUCCESS;

cleanup:
  talloc_free(tmp_ctx);
  if ((rc != TRP_SUCCESS) && (msg_body != NULL))
    msg_body->records=NULL; /* don't leave this hanging */

  return rc;
}

/* pretty print */
static void trp_msg_info_route_print(void *rec_in)
{
  TRP_MSG_INFO_ROUTE *rec=talloc_get_type(rec_in, TRP_MSG_INFO_ROUTE); /* null if wrong type */

  if (rec!=NULL) {
    printf("     community=%.*s\n     realm=%.*s\n     trust_router=%.*s\n     metric=%d\n     interval=%d]\n",
           rec->comm->len, rec->comm->buf,
           rec->realm->len, rec->realm->buf,
           rec->trust_router->len, rec->trust_router->buf,
           rec->metric, rec->interval);
  }
}


static int trp_route_req_destructor(void *object)
{
  TRP_ROUTE_REQ *body=talloc_get_type_abort(object, TRP_ROUTE_REQ);
  
  /* clean up TR_NAME data, which are not managed by talloc */
  if (body->comm != NULL) {
    tr_free_name(body->comm);
    body->comm=NULL;
    tr_debug("trp_route_req_destructor: freed community");
  }
  if (body->realm != NULL) {
    tr_free_name(body->realm);
    body->realm=NULL;
    tr_debug("trp_route_req_destructor: freed realm");
  }
  return 0;
}

void *trp_route_req_new(TALLOC_CTX *mem_ctx)
{
  TRP_ROUTE_REQ *new_body=talloc(mem_ctx, TRP_ROUTE_REQ);

  if (new_body != NULL) {
    new_body->comm=NULL;
    new_body->realm=NULL;
  }

  talloc_set_destructor((void *)new_body, trp_route_req_destructor);
  return new_body;
}

void trp_route_req_set_comm(TRP_ROUTE_REQ *req, TR_NAME *comm)
{
  req->comm=comm;
}

void trp_route_req_set_realm(TRP_ROUTE_REQ *req, TR_NAME *realm)
{
  req->realm=realm;
}

/* TODO: clean up return codes. 
 * TODO: should take a body, not a msg */
static TRP_RC trp_parse_route_req(TRP_MSG *msg, json_t *jbody)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_ROUTE_REQ *msg_body=NULL;
  char *s=NULL;
  TRP_RC rc=TRP_ERROR;

  /* check message type and body type for agreement */
  if (msg->type != TRP_MSG_TYPE_ROUTE_REQ) {
    rc=TRP_BADTYPE;
    goto cleanup;
  }
  msg_body=talloc_get_type(msg->body, TRP_ROUTE_REQ);
  if (msg_body==NULL) {
    rc=TRP_BADTYPE;
    goto cleanup;
  }

  rc=trp_get_json_string(jbody, "community", &s, tmp_ctx);
  if (rc!=TRP_SUCCESS)
    goto cleanup;
  msg_body->comm=tr_new_name(s);
  talloc_free(s); s=NULL;

  rc=trp_get_json_string(jbody, "realm", &s, tmp_ctx);
  if (rc!=TRP_SUCCESS)
    goto cleanup;
  msg_body->realm=tr_new_name(s);
  talloc_free(s); s=NULL;

  rc=TRP_SUCCESS;
cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

static json_t *trp_encode_body(TRP_MSG_TYPE type, void *body)
{
  struct trp_msg_type_entry *msgtype=get_trp_msg_type_entry(type);

  if ((msgtype->type==TRP_MSG_TYPE_UNKNOWN) || (msgtype->encode==NULL))
    return NULL;

  tr_debug("trp_encode_body: encoding type %s", trp_msg_type_to_string(type));

  return msgtype->encode(body);
}

char *trp_encode_msg(TRP_MSG *msg)
{
  json_t *jmsg=NULL;
  json_t *jtype=NULL;
  json_t *jbody=NULL;
  char *encoded=NULL;

  jbody=trp_encode_body(msg->type, msg->body);
  if (jbody!=NULL) {
    jmsg=json_object();
    if (jmsg==NULL) {
      /* failed */
      json_decref(jbody);
    } else {
      jtype=json_string(trp_msg_type_to_string(msg->type));
      if (jtype==NULL) {
        json_decref(jbody);
      } else {
        json_object_set_new(jmsg, "message_type", jtype);
        json_object_set_new(jmsg, "body", jbody);
        encoded=json_dumps(jmsg, 0);
      }
      json_decref(jmsg);
    }
  }
  return encoded;
}

/* add record data to jrec */
static TRP_RC trp_encode_info_route(json_t *jrec, void *route_in)
{
  TRP_MSG_INFO_ROUTE *route=talloc_get_type(route_in, TRP_MSG_INFO_ROUTE);
  json_t *jstr=NULL;
  json_t *jint=NULL;
  char *s=NULL;

  if (route==NULL)
    return TRP_BADTYPE;

  s=tr_name_strdup(route->comm);
  if (s==NULL)
    return TRP_NOMEM;
  jstr=json_string(s);
  free(s);s=NULL;
  if(jstr==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "community", jstr);

  s=tr_name_strdup(route->realm);
  if (s==NULL)
    return TRP_NOMEM;
  jstr=json_string(s);
  free(s);s=NULL;
  if(jstr==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "realm", jstr);

  s=tr_name_strdup(route->trust_router);
  if (s==NULL)
    return TRP_NOMEM;
  jstr=json_string(s);
  free(s);s=NULL;
  if(jstr==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "trust_router", jstr);

  jint=json_integer(route->metric);
  if(jint==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "metric", jint);

  jint=json_integer(route->interval);
  if(jint==NULL)
    return TRP_ERROR;
  json_object_set_new(jrec, "interval", jint);

  return TRP_SUCCESS;
}

static json_t *trp_encode_info_rec(TRP_MSG_INFO_REC *rec)
{
  struct trp_msg_info_type_entry *rectype=get_trp_msg_info_type_entry(rec->type);
  json_t *jrec=NULL;
  json_t *jstr=NULL;

  if (rectype->type==TRP_MSG_INFO_TYPE_UNKNOWN)
    return NULL;

  jrec=json_object();
  if (jrec==NULL)
    return NULL;

  jstr=json_string(trp_msg_info_type_to_string(rec->type));
  if (jstr==NULL) {
    json_decref(jrec);
    return NULL;
  }
  json_object_set_new(jrec, "record_type", jstr);

  if ((rectype->encode==NULL) || (TRP_SUCCESS!=rectype->encode(jrec, rec->data))) {
    json_decref(jrec);
    return NULL;
  }

  return jrec;
}

static json_t *trp_encode_route_update(void *update_in)
{
  TRP_ROUTE_UPDATE *update=talloc_get_type(update_in, TRP_ROUTE_UPDATE); /* null if wrong type */
  json_t *jbody=NULL;
  json_t *jrecords=NULL;
  json_t *jrec=NULL;

  if (update==NULL)
    return NULL;

  jbody=json_object();
  if (jbody==NULL)
    return NULL;

  jrecords=json_array();

  return jbody;
}

static json_t *trp_encode_route_req(void *req_in)
{
  TRP_ROUTE_REQ *req=talloc_get_type(req_in, TRP_ROUTE_REQ); /* null if wrong type */
  json_t *jbody=NULL;
  json_t *jstr=NULL;
  char *s=NULL;

  if (req==NULL)
    return NULL;

  jbody=json_object();
  if (jbody==NULL)
    return NULL;

  s=tr_name_strdup(req->comm); /* ensures null termination */
  if (s==NULL) {
    json_decref(jbody);
    return NULL;
  }
  jstr=json_string(s);
  free(s); s=NULL;
  if (jstr==NULL) {
    json_decref(jbody);
    return NULL;
  }
  json_object_set_new(jbody, "community", jstr);
    
  s=tr_name_strdup(req->realm); /* ensures null termination */
  if (s==NULL) {
    json_decref(jbody);
    return NULL;
  }
  jstr=json_string(s);
  free(s); s=NULL;
  if (jstr==NULL) {
    json_decref(jbody);
    return NULL;
  }
  json_object_set_new(jbody, "realm", jstr);

  return jbody;
}

static void trp_msg_info_rec_print(TRP_MSG_INFO_REC *rec)
{
  struct trp_msg_info_type_entry *rectype=get_trp_msg_info_type_entry(rec->type);

  if (rectype->print != NULL) {
    printf("    [record_type=%s\n", trp_msg_info_type_to_string(rec->type));
    rectype->print(rec->data);
  }
  else
    printf("    [record_type=%s, (no print method)]\n");
}

static void trp_route_update_print(void *body_in)
{
  TRP_ROUTE_UPDATE *body=talloc_get_type(body_in, TRP_ROUTE_UPDATE); /* null if wrong type */
  TRP_MSG_INFO_REC *rec=NULL;

  if (body!=NULL) {
    printf("  {records=\n");
    for (rec=body->records; rec!=NULL; rec=rec->next) 
      trp_msg_info_rec_print(rec);
    printf("  }\n");
  }
}

static void trp_route_req_print(void *body_in)
{
  TRP_ROUTE_REQ *body=talloc_get_type(body_in, TRP_ROUTE_REQ); /* null if wrong type */

  if (body!=NULL) {
    printf("  {community=%.*s\n   realm=%.*s}\n",
           body->comm->len, body->comm->buf,
           body->realm->len, body->realm->buf);
  }
}

static void trp_msg_body_print(void *body, TRP_MSG_TYPE msgtype)
{
  struct trp_msg_type_entry *info=get_trp_msg_type_entry(msgtype);
  info->print(body);
}

void trp_msg_print(TRP_MSG *msg)
{
  /* right now just assumes update */
  printf("{message_type=%s\n", trp_msg_type_to_string(msg->type));
  trp_msg_body_print(msg->body, msg->type);
  printf("}\n");
}

/* returns a pointer to one of the message body types, or NULL on error/unknown type */
static void *trp_msg_body_new(TALLOC_CTX *mem_ctx, TRP_MSG_TYPE msgtype)
{
  void *new_body=NULL;
  struct trp_msg_type_entry *info=get_trp_msg_type_entry(msgtype);

  if (info->type==TRP_MSG_TYPE_UNKNOWN) {
    tr_debug("trp_msg_body_new: Unknown type %d.", info->type);
    return NULL;
  }

  new_body=info->allocate(mem_ctx);
  msg_body_type_check(msgtype, new_body); /* aborts program on type violation */
  return new_body;
}

/* call the correct parser */
static TRP_RC trp_parse_msg_body(TRP_MSG *msg, json_t *jbody)
{
  struct trp_msg_type_entry *info=get_trp_msg_type_entry(msg->type);

  if (info->type==TRP_MSG_TYPE_UNKNOWN) {
    tr_debug("trp_msg_body_parse: Unknown type %d.", info->type);
    return TRP_ERROR;
  }

  return info->parse(msg, jbody);
}


TRP_RC trp_parse_msg(TALLOC_CTX *mem_ctx, const char *buf, size_t buflen, TRP_MSG **msg) 
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_MSG *new_msg=NULL;
  TRP_RC msg_rc=TRP_ERROR;
  json_error_t json_err;
  json_t *jmsg=NULL; /* handle for the whole msg */
  json_t *jbody=NULL;
  char *s;

  tr_debug("trp_parse_msg: parsing %d bytes", buflen);

  jmsg=json_loadb(buf, buflen, 0, &json_err);
  if (jmsg == NULL) {
    tr_debug("trp_parse_msg: Error parsing message.");
    msg_rc=TRP_NOPARSE;
    goto cleanup;
  }

  /* parse the common part of the message */
  new_msg=trp_msg_new(tmp_ctx);
  if (new_msg == NULL) {
    tr_debug("trp_parse_msg: Error allocating message.");
    msg_rc=TRP_NOMEM;
    goto cleanup;
  }

  switch (trp_get_json_string(jmsg, "message_type", &s, new_msg)) {
  case TRP_SUCCESS:
    break;
  case TRP_NOPARSE:
    tr_debug("trp_parse_msg: required attribute 'message_type' not present.");
    msg_rc=TRP_NOPARSE;
    goto cleanup;
  case TRP_BADTYPE:
    tr_debug("trp_parse_msg: required attribute 'message_type' is not a string.");
    msg_rc=TRP_NOPARSE;
    goto cleanup;
  default:
    tr_debug("trp_parse_msg: error parsing 'message_type'.");
    msg_rc=TRP_NOPARSE;
    goto cleanup;
  }
  
  tr_debug("trp_parse_msg: 'message_type' is '%s'", s);
  new_msg->type = trp_msg_type_from_string(s);
  if (new_msg->type==TRP_MSG_TYPE_UNKNOWN) {
    tr_debug("trp_parse_msg: Parsing error, unknown message_type (%s).", s);
    msg_rc=TRP_NOPARSE;
    goto cleanup;
  }  

  new_msg->body=trp_msg_body_new(new_msg, new_msg->type);
  if (new_msg->body==NULL) {
    tr_debug("trp_parse_msg: Error allocating message body for message_type %d.", new_msg->type);
    msg_rc=TRP_NOMEM;
    goto cleanup;
  }
  jbody=json_object_get(jmsg, "body");
  if (jbody==NULL) {
    tr_debug("trp_parse_msg: Message body not found.");
    msg_rc=TRP_NOPARSE;
    goto cleanup;
  }

  switch (trp_parse_msg_body(new_msg, jbody)) {
  case TRP_SUCCESS:
    break;
  default:
    tr_debug("trp_parse_msg: Error parsing message body.");
    goto cleanup;
  }

  /* success! */
  (*msg)=new_msg;
  new_msg=NULL;
  talloc_steal(mem_ctx, *msg);
  msg_rc=TRP_SUCCESS;

cleanup:
  talloc_free(tmp_ctx);
  json_decref(jmsg);
  return msg_rc;
}
