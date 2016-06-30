#include <fcntl.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>

#include <gsscon.h>
#include <tr_rp.h>
#include <tr_debug.h>
#include <trp_internal.h>


TRPS_INSTANCE *trps_new (TALLOC_CTX *mem_ctx)
{
  TRPS_INSTANCE *trps=talloc(mem_ctx, TRPS_INSTANCE);
  if (trps!=NULL)  {
    trps->hostname=NULL;
    trps->port=0;
    trps->cookie=NULL;
    trps->conn=NULL;
    trps->trpc=NULL;
    trps->mq=tr_mq_new(trps);
    if (trps->mq==NULL) {
      /* failed to allocate mq */
      talloc_free(trps);
      trps=NULL;
    }
  }
  return trps;
}

void trps_free (TRPS_INSTANCE *trps)
{
  if (trps!=NULL)
    talloc_free(trps);
}

TR_MQ_MSG *trps_mq_pop(TRPS_INSTANCE *trps)
{
  return tr_mq_pop(trps->mq);
}

void trps_mq_append(TRPS_INSTANCE *trps, TR_MQ_MSG *msg)
{
  tr_mq_append(trps->mq, msg);
}

/* stand-in for a function that finds the connection for a particular peer */
#if 0
static TRP_CONNECTION *trps_find_connection(TRPS_INSTANCE *trps)
{
  return trps->conn;
}
#endif

void trps_add_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *new)
{
  if (trps->conn==NULL)
    trps->conn=new;
  else
    trp_connection_append(trps->conn, new);

  talloc_steal(trps, new);
}

/* ok to call more than once; guarantees connection no longer in the list.
 * Caller is responsible for freeing the removed element afterwards.  */
void trps_remove_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *remove)
{
  trps->conn=trp_connection_remove(trps->conn, remove);
}

void trps_add_trpc(TRPS_INSTANCE *trps, TRPC_INSTANCE *trpc)
{
  if (trps->trpc==NULL)
    trps->trpc=trpc;
  else
    trpc_append(trps->trpc, trpc);

  talloc_steal(trps, trpc);
}

/* ok to call more than once; guarantees trpc no longer in the list.
 * Caller is responsible for freeing the removed element afterwards.  */
void trps_remove_trpc(TRPS_INSTANCE *trps, TRPC_INSTANCE *remove)
{
  trps->trpc=trpc_remove(trps->trpc, remove);
}

TRP_RC trps_send_msg (TRPS_INSTANCE *trps, void *peer, const char *msg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_MQ_MSG *mq_msg=NULL;
  char *msg_dup=NULL;
  TRP_RC rc=TRP_ERROR;

  /* Currently ignore peer and just send to an open connection.
   * In reality, need to identify the correct peer and send via that
   * one.  */
  if (trps->trpc != NULL) {
    if (trpc_get_status(trps->trpc)!=TRP_CONNECTION_UP)
      tr_debug("trps_send_msg: skipping message sent while TRPC connection not up.");
    else {
      mq_msg=tr_mq_msg_new(tmp_ctx, "trpc_send");
      msg_dup=talloc_strdup(mq_msg, msg); /* get local copy in mq_msg context */
      tr_mq_msg_set_payload(mq_msg, msg_dup, NULL); /* no need for a free() func */
      trpc_mq_append(trps->trpc, mq_msg);
      rc=TRP_SUCCESS;
    }
  }
  talloc_free(tmp_ctx);
  return rc;
}

static int trps_listen (TRPS_INSTANCE *trps, int port) 
{
    int rc = 0;
    int conn = -1;
    int optval = 1;

    union {
      struct sockaddr_storage storage;
      struct sockaddr_in in4;
    } addr;

    struct sockaddr_in *saddr = (struct sockaddr_in *) &addr.in4;

    saddr->sin_port = htons (port);
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = INADDR_ANY;

    if (0 > (conn = socket (AF_INET, SOCK_STREAM, 0)))
      return conn;

    setsockopt(conn, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (0 > (rc = bind (conn, (struct sockaddr *) saddr, sizeof(struct sockaddr_in))))
      return rc;

    if (0 > (rc = listen(conn, 512)))
      return rc;

    tr_debug("trps_listen: TRP Server listening on port %d", port);
    return conn;
}

/* returns EACCES if authorization is denied */
int trps_auth_cb(gss_name_t clientName, gss_buffer_t displayName, void *data)
{
  TRPS_INSTANCE *inst = (TRPS_INSTANCE *)data;
  int result=0;

  if (0!=inst->auth_handler(clientName, displayName, inst->cookie)) {
    tr_debug("trps_auth_cb: client '%.*s' denied authorization.", displayName->length, displayName->value);
    result=EACCES; /* denied */
  }

  return result;
}

static TRP_RC trps_read_message(TRPS_INSTANCE *trps, TRP_CONNECTION *conn, TR_MSG **msg)
{
  int err=0;
  char *buf=NULL;
  size_t buflen = 0;

  tr_debug("trps_read_message: started");
  if (err = gsscon_read_encrypted_token(trp_connection_get_fd(conn),
                                       *(trp_connection_get_gssctx(conn)), 
                                        &buf,
                                        &buflen)) {
    tr_debug("trps_read_message: error");
    if (buf)
      free(buf);
    return TRP_ERROR;
  }

  tr_debug("trps_read_message(): Request Received, %u bytes.", (unsigned) buflen);
  tr_debug("trps_read_message(): %.*s", buflen, buf);

  *msg=tr_msg_decode(buf, buflen);
  free(buf);
  if (*msg==NULL)
    return TRP_NOPARSE;

  /* fill in the next hop as the peer who just sent this to us */
  trp_inforec_set_next_hop(*msg, trp_connection_get_peer(conn));
  return TRP_SUCCESS;
}

int trps_get_listener(TRPS_INSTANCE *trps,
                      TRPS_MSG_FUNC msg_handler,
                      TRP_AUTH_FUNC auth_handler,
                      const char *hostname,
                      unsigned int port,
                      void *cookie)
{
  int listen = -1;

  if (0 > (listen = trps_listen(trps, port))) {
    char errbuf[256];
    if (0 == strerror_r(errno, errbuf, 256)) {
      tr_debug("trps_get_listener: Error opening port %d: %s.", port, errbuf);
    } else {
      tr_debug("trps_get_listener: Unknown error openining port %d.", port);
    }
  } 

  if (listen > 0) {
    /* opening port succeeded */
    tr_debug("trps_get_listener: Opened port %d.", port);
    
    /* make this socket non-blocking */
    if (0 != fcntl(listen, F_SETFL, O_NONBLOCK)) {
      tr_debug("trps_get_listener: Error setting O_NONBLOCK.");
      close(listen);
      listen=-1;
    }
  }

  if (listen > 0) {
    /* store the caller's request handler & cookie */
    trps->msg_handler = msg_handler;
    trps->auth_handler = auth_handler;
    trps->hostname = talloc_strdup(trps, hostname);
    trps->port = port;
    trps->cookie = cookie;
  }

  return listen;
}

void trps_handle_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *conn)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_MSG *msg=NULL;
  TRP_RC rc=TRP_ERROR;

  /* try to establish a GSS context */
  if (0!=trp_connection_auth(conn, trps->auth_handler, trps->cookie)) {
    tr_notice("tr_trps_conn_thread: failed to authorize connection");
    pthread_exit(NULL);
  }
  tr_notice("trps_handle_connection: authorized connection");
  
  /* loop as long as the connection exists */
  while (trp_connection_get_status(conn)==TRP_CONNECTION_UP) {
    rc=trps_read_message(trps, conn, &msg);
    switch(rc) {
    case TRP_SUCCESS:
      trps->msg_handler(trps, conn, msg); /* send the TR_MSG off to the callback */
      break;

    case TRP_ERROR:
      trp_connection_close(conn);
      break;

    default:
      tr_debug("trps_handle_connection: trps_read_message failed (%d)", rc);
    }
  }

  tr_debug("trps_handle_connection: connection closed.");
  talloc_free(tmp_ctx);
}
