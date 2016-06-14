#include <talloc.h>

#include <trp_internal.h>
#include <tr_debug.h>


/* static prototypes */
static void *trp_msg_body_update_new(TALLOC_CTX *mem_ctx);
static void *trp_msg_body_route_req_new(TALLOC_CTX *mem_ctx);

/* table of string names for TMT_MSG_TYPE codes */
struct trp_msg_type_info {
  const char *name;
  TRP_MSG_TYPE type;
  void *(*allocator)(TALLOC_CTX *);
};

static struct trp_msg_type_info trp_msg_type_table[] = {
  { "update", TRP_MSG_TYPE_UPDATE, trp_msg_body_update_new },
  { "route_req", TRP_MSG_TYPE_ROUTE_REQ, trp_msg_body_route_req_new },
  { NULL, TRP_MSG_TYPE_UNKNOWN, NULL } /* must be the last entry */
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

/* placeholder return type */
static int trp_parse_msg_update(json_t *jmsg)
{
  
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


TRP_RC trp_parse_msg(TALLOC_CTX *mem_ctx, const char *buf, size_t buflen, TRP_MSG **msg) 
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_MSG *new_msg=NULL;
  TRP_RC msg_rc=TRP_ERROR;
  json_error_t json_err;
  json_t *jmsg=NULL; /* handle for the whole msg */
  json_t *jmsgtype=NULL;

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

  jmsgtype=json_object_get(jmsg, "message_type");
  if (jmsgtype == NULL) {
    msg_rc=TRP_NOPARSE;
    goto cleanup;
  }

  /* get the message type */
  if (!json_is_string(jmsgtype)) {
    tr_debug("trp_parse_msg: Parsing error, message_type is not a string.");
    msg_rc=TRP_NOPARSE;
    goto cleanup;
  }

  tr_debug("trp_parse_msg: message_type: %s", json_string_value(jmsgtype));

  new_msg->type = trp_msg_type_from_string(json_string_value(jmsgtype));
  if (new_msg->type==TRP_MSG_TYPE_UNKNOWN) {
    tr_debug("trp_parse_msg: Parsing error, unknown message_type (%s).", json_string_value(jmsgtype));
    msg_rc=TRP_NOPARSE;
    goto cleanup;
  }  

  /* next line uses new_msg as the talloc context so body will free along with msg */
  new_msg->body=trp_msg_body_new(new_msg, new_msg->type);
  if (new_msg->body==NULL) {
    tr_debug("trp_parse_msg: Error allocating message body for message_type %d.", new_msg->type);
    msg_rc=TRP_NOMEM;
    goto cleanup;
  }

  tr_debug("trp_parse_msg: SUCCESS");

  /* success! */
  (*msg)=new_msg;
  new_msg=NULL;
  talloc_steal(mem_ctx, *msg);

cleanup:
  talloc_free(tmp_ctx);
  return msg_rc;
}
