#include <fcntl.h>
#include <event2/event.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>

#include <gsscon.h>
#include <tr_rp.h>
#include <tr_event.h>
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

int trps_send_msg (TRPS_INSTANCE *trps,
                   int conn,
                   gss_ctx_id_t gssctx,
                   const char *msg_content)
{
  int err=0;
  int rc=0;

  /* Send the request over the connection */
  if (err = gsscon_write_encrypted_token (conn,
                                          gssctx,
                                          msg_content, 
                                          strlen(msg_content))) {
    tr_err( "trps_send_msg: Error sending message over connection.\n");
    rc = -1;
  }

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

#if 0
static int trps_read_message (TRPS_INSTANCE *trps, int conn, gss_ctx_id_t *gssctx, char **msg)
{
  int err;
  char *buf;
  size_t buflen = 0;

  if (err = gsscon_read_encrypted_token(conn, *gssctx, &buf, &buflen)) {
    if (buf)
      free(buf);
    return -1;
  }

  tr_debug("trps_read_request(): Request Received, %u bytes.", (unsigned) buflen);
  tr_debug("trps_read_request(): %.*s", buflen, buf);

  *msg=talloc_strndup(NULL, buf, buflen); /* no context owns this! */
  free(buf);
  return buflen;
}
#endif

int trps_get_listener(TRPS_INSTANCE *trps,
                      TRP_REQ_FUNC req_handler,
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
    trps->req_handler = req_handler;
    trps->auth_handler = auth_handler;
    trps->hostname = talloc_strdup(trps, hostname);
    trps->port = port;
    trps->cookie = cookie;
  }

  return listen;
}

/* old cruft */
#if 0
static gss_ctx_id_t trps_establish_gss_context (TRPS_INSTANCE *trps, int conn)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  gss_ctx_id_t gssctx = GSS_C_NO_CONTEXT;
  char *msg_rec=NULL;
  int msg_len = 0;
  int rc=0;

  if (trps_auth_connection(trps, conn, &gssctx))
    tr_notice("trps_establish_gss_context: Error authorizing TID Server connection.");
  else:
    tr_notice("trps_establish_gss_context: Connection authorized!");
  return gssctx;

  msg_len = trps_read_message(trps, conn, &gssctx, &msg_rec);
  talloc_steal(tmp_ctx, msg_rec); /* get this in our context */
  if (0 > msg_len) {
    tr_debug("trps_handle_connection: Error from trps_read_message()");
    goto cleanup;
  }
  
  tr_debug("trps_handle_connection: msg_len=%d", msg_len);
  reply=talloc_asprintf(tmp_ctx, "TRPS heard: %.*s", msg_len, msg_rec);
  if (0 > (rc = trps_send_msg(trps, conn, gssctx, reply))) {
    tr_debug("trps_handle_connection: Error from trps_send_message(), rc = %d.", rc);
  }

cleanup:
  talloc_free(tmp_ctx);
  return conn;
}
#endif
