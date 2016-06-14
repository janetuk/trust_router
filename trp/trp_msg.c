#include <talloc.h>

#include <trp_internal.h>
#include <tr_debug.h>


/* static prototypes */
static void *trp_msg_body_update_new(TALLOC_CTX *mem_ctx);
static TRP_RC trp_parse_update(TRP_MSG *msg, json_t *jmsg);

static void *trp_msg_body_route_req_new(TALLOC_CTX *mem_ctx);
static TRP_RC trp_parse_route_req(TRP_MSG *msg, json_t *jmsg);


/* table of string names for TMT_MSG_TYPE codes */
struct trp_msg_type_info {
  const char *name;
  TRP_MSG_TYPE type;
  void *(*allocator)(TALLOC_CTX *);
  TRP_RC (*parser)(TRP_MSG *, json_t *);
};

static struct trp_msg_type_info trp_msg_type_table[] = {
  { "update", TRP_MSG_TYPE_UPDATE, trp_msg_body_update_new, trp_parse_update },
  { "route_req", TRP_MSG_TYPE_ROUTE_REQ, trp_msg_body_route_req_new, trp_parse_route_req },
  { NULL, TRP_MSG_TYPE_UNKNOWN, NULL, NULL } /* must be the last entry */
};

/* Use talloc's dynamic type checking to verify type.
 * By default, this will cause program abort, but can be overridden
 * via talloc_set_abort_fn() if more graceful handling is needed. */
static void msg_body_type_check(TRP_MSG_TYPE msgtype, void *p)
{
  switch (msgtype) {
  case TRP_MSG_TYPE_UPDATE:
    talloc_get_type_abort(p, TRP_MSG_BODY_UPDATE);
    break;

  case TRP_MSG_TYPE_ROUTE_REQ:
    talloc_get_type_abort(p, TRP_MSG_BODY_ROUTE_REQ);
    break;

  default:
    break;
  }
}

/* look up an entry in the trp_msg_type_table */
static struct trp_msg_type_info *get_trp_msg_type_info(TRP_MSG_TYPE msgtype)
{
  struct trp_msg_type_info *entry=trp_msg_type_table;

  while ((entry->type != TRP_MSG_TYPE_UNKNOWN)
        && (entry->type != msgtype)) {
    entry ++;
  }
  return entry;
}

/* translate strings to codes */
TRP_MSG_TYPE trp_msg_type_from_string(const char *s)
{
  struct trp_msg_type_info *entry=trp_msg_type_table;

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
  struct trp_msg_type_info *entry=get_trp_msg_type_info(msgtype);
  return entry->name;
}


TRP_MSG *trp_msg_new(TALLOC_CTX *mem_ctx)
{
  TRP_MSG *new_msg=talloc(mem_ctx, TRP_MSG);

  if (new_msg != NULL) {
    new_msg->type=TRP_MSG_TYPE_UNKNOWN;
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
static TRP_RC trp_get_json_integer(json_t *msg, const char *attr, int *dest)
{
  return TRP_ERROR;
}

/* Read attribute attr from msg as a string */
static TRP_RC trp_get_json_string(json_t *jmsg, const char *attr, const char **dest)
{
  json_error_t err;
  json_t *obj;

  obj=json_object_get(jmsg, attr);
  if (obj == NULL) {
    return TRP_NOPARSE;
  }
  /* check type */
  if (!json_is_string(obj)) {
    return TRP_BADTYPE;
  }

  (*dest)=json_string_value(obj);
  return TRP_SUCCESS;
}



static void *trp_msg_body_update_new(TALLOC_CTX *mem_ctx)
{
  TRP_MSG_BODY_UPDATE *new_body=talloc(mem_ctx, TRP_MSG_BODY_UPDATE);

  if (new_body != NULL) {
    new_body->next=NULL;
    new_body->community=NULL;
    new_body->realm=NULL;
    new_body->trust_router=NULL;
    new_body->metric=TRP_METRIC_INFINITY;
    new_body->interval=0;
  }
  return new_body;
}

/* parse a single record */
static TRP_RC trp_parse_update_record(TRP_MSG_BODY_UPDATE *body, json_t *jrecord)
{
  return TRP_SUCCESS;
}

/* Parse an update body. Creates a linked list of records as the body, allocating all but the first.
 * Hence, msg->body must be allocated as a TRP_MSG_BODY_UPDATE. All body records will be in the
 * talloc context of msg.
 *
 * An error will be returned if any unparseable records are encountered. 
 *
 * TODO: clean up return codes. */
static TRP_RC trp_parse_update(TRP_MSG *msg, json_t *jbody)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  json_t *jrecords=NULL;
  json_t *jval=NULL; /* for iteration */
  size_t ii=0;
  size_t nrec=0;
  TRP_MSG_BODY_UPDATE *msg_body=NULL;
  TRP_MSG_BODY_UPDATE *cur_body=NULL;
  TRP_RC rc=TRP_ERROR;

  if (msg->type != TRP_MSG_TYPE_UPDATE) {
    rc=TRP_BADTYPE;
    goto cleanup;
  }

  jrecords=json_object_get(jbody, "records");
  if ((jrecords==NULL) || (!json_is_array(jrecords))) {
    rc=TRP_NOPARSE;
    goto cleanup;
  }

  /* process the array */
  /* first body is already allocated by caller. Check that it is expected type */
  msg_body=talloc_get_type(msg->body, TRP_MSG_BODY_UPDATE);
  if (msg_body==NULL) {
    rc=TRP_BADTYPE;
    goto cleanup;
  }

  cur_body=msg_body;
  nrec=json_array_size(jrecords);
  for (ii=0; ii<nrec; ii++) {
    jval=json_array_get(jrecords, ii);
    if (ii>0) {
      /* on all but the first, need to allocate space */
      cur_body->next=trp_msg_body_update_new(tmp_ctx);
      if (cur_body==NULL) {
        rc=TRP_NOMEM;
        goto cleanup;
      }
      cur_body=cur_body->next;
    }

    if (TRP_SUCCESS != trp_parse_update_record(cur_body, jval)) {
      rc=TRP_NOPARSE;
      goto cleanup;
    }
  }

  /* Succeeded. Move all of our new allocations into the correct talloc context */
  for (cur_body=msg_body->next; cur_body != NULL; cur_body=cur_body->next)
    talloc_steal(msg, cur_body); /* all successfully parsed bodies belong to msg context */
  rc=TRP_SUCCESS;

cleanup:
  talloc_free(tmp_ctx);
  if (rc != TRP_SUCCESS)
    msg_body->next=NULL; /* don't leave this hanging */

  return rc;
}


static void *trp_msg_body_route_req_new(TALLOC_CTX *mem_ctx)
{
  TRP_MSG_BODY_ROUTE_REQ *new_body=talloc(mem_ctx, TRP_MSG_BODY_ROUTE_REQ);

  if (new_body != NULL) {
    new_body->community=NULL;
    new_body->realm=NULL;
  }
  return new_body;
}

static TRP_RC trp_parse_route_req(TRP_MSG *msg, json_t *jbody)
{
  return TRP_ERROR;
}



/* returns a pointer to one of the message body types, or NULL on error/unknown type */
static void *trp_msg_body_new(TALLOC_CTX *mem_ctx, TRP_MSG_TYPE msgtype)
{
  void *new_body=NULL;
  struct trp_msg_type_info *info=get_trp_msg_type_info(msgtype);

  if (info->type==TRP_MSG_TYPE_UNKNOWN) {
    tr_debug("trp_msg_body_new: Unknown type %d.", info->type);
    return NULL;
  }

  new_body=info->allocator(mem_ctx);
  msg_body_type_check(msgtype, new_body); /* aborts program on type violation */
  return new_body;
}

/* call the correct parser */
static TRP_RC trp_parse_msg_body(TRP_MSG *msg, json_t *jbody)
{
  struct trp_msg_type_info *info=get_trp_msg_type_info(msg->type);

  if (info->type==TRP_MSG_TYPE_UNKNOWN) {
    tr_debug("trp_msg_body_parse: Unknown type %d.", info->type);
    return TRP_ERROR;
  }

  return info->parser(msg, jbody);
}


TRP_RC trp_parse_msg(TALLOC_CTX *mem_ctx, const char *buf, size_t buflen, TRP_MSG **msg) 
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_MSG *new_msg=NULL;
  TRP_RC msg_rc=TRP_ERROR;
  json_error_t json_err;
  json_t *jmsg=NULL; /* handle for the whole msg */
  json_t *jbody=NULL;
  const char *s;

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

  switch (trp_get_json_string(jmsg, "message_type", &s)) {
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

cleanup:
  talloc_free(tmp_ctx);
  return msg_rc;
}
