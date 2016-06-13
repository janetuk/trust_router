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

/* connections and sets of connections */
TRPS_CONNECTION *trps_connection_new(TALLOC_CTX *mem_ctx)
{
  TRPS_CONNECTION *new_conn=talloc_new(mem_ctx, TRPS_CONNECTION);

  if (new_conn != NULL) {
    new_conn->conn=-1;
    new_conn->gssctx=0;
  }

  return new_conn;
}



TRPS_CONNECTION_SET *trps_connection_set_new(TALLOC_CTX *mem_ctx)
{
  TRPS_CONNECTION_SET *new_set=talloc_new(mem_ctx, TRPS_CONNECTION_SET);
  int ii=0;

  if (new_set != NULL) {
    new_set->nconn=0;
    for(ii=0; ii<TRPS_CONNECTIONS_MAX; ii++)
      new_set->conn[ii]=0;
  }

  return new_set;
}

TRPS_ERR trps_connection_set_add(TRPS_CONNECTION_SET *tcs, TRPS_CONNECTION *new_conn)
{
  TR_ERR err=TRPS_ERR_OK;

  if (tcs->nconn < TRPS_CONNECTIONS_MAX) {
    tcs->conn[tcs->nconn]=new_conn;
    talloc_steal(tcs, new_conn);
    tcs->nconn++;
  } else {
    err=TRPS_ERR_MAX_CONN;
  }

  return err;
}

int trps_connection_set_del(TRPS_CONNECTION_SET *tcs, TRPS_CONNECTION *conn)
{
  /* not implemented */
  return TRPS_ERR_UNKNOWN;
}

int trps_connection_set_len(TRPS_CONNECTION_SET *tcs)
{
  return tcs->nconn;
}




TRPS_INSTANCE *trps_create (TALLOC_CTX *mem_ctx)
{
  return talloc_zero(mem_ctx, TRPS_INSTANCE);
}

void trps_destroy (TRPS_INSTANCE *trps)
{
  if (trps)
    talloc_free(trps);
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
static int trps_auth_cb(gss_name_t clientName, gss_buffer_t displayName,
                        void *data)
{
  TRPS_INSTANCE *inst = (TRPS_INSTANCE *)data;
  TR_NAME name ={(char *) displayName->value,
                 displayName->length};
  int result=0;

  if (0!=inst->auth_handler(clientName, &name, inst->cookie)) {
    tr_debug("trps_auth_cb: client '%.*s' denied authorization.", name.len, name.buf);
    result=EACCES; /* denied */
  }

  return result;
}

/* returns 0 on authorization success, 1 on failure, or -1 in case of error */
static int trps_auth_connection (TRPS_INSTANCE *inst,
                                 int conn,
                                 gss_ctx_id_t *gssctx)
{
  int rc = 0;
  int auth, autherr = 0;
  gss_buffer_desc nameBuffer = {0, NULL};
  char *name = 0;
  int nameLen = 0;

  nameLen = asprintf(&name, "trustrouter@%s", inst->hostname);
  nameBuffer.length = nameLen;
  nameBuffer.value = name;
  
  if (rc = gsscon_passive_authenticate(conn, nameBuffer, gssctx, trps_auth_cb, inst)) {
    tr_debug("trps_auth_connection: Error from gsscon_passive_authenticate(), rc = %d.", rc);
    return -1;
  }

  if (rc = gsscon_authorize(*gssctx, &auth, &autherr)) {
    tr_debug("trps_auth_connection: Error from gsscon_authorize, rc = %d, autherr = %d.", 
	    rc, autherr);
    return -1;
  }

  if (auth)
    tr_debug("trps_auth_connection: Connection authenticated, conn = %d.", conn);
  else
    tr_debug("trps_auth_connection: Authentication failed, conn %d.", conn);

  return !auth;
}

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

static int trps_get_listener(TRPS_INSTANCE *trps,
                             TRPS_REQ_FUNC *req_handler,
                             trps_auth_func *auth_handler,
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


/* Accept and process a connection on a port opened with trps_get_listener().
 * Returns the socket FD, or -1 in case of error. */
int trps_accept(TRPS_INSTANCE *trps, int listen)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  int conn=-1;
  gss_ctx_id_t gssctx;
  TRPS_CONNECTION *trps_conn=0;
  TRPS_ERR trps_err=TRPS_ERR_OK;

  conn = accept(listen, NULL, NULL);

  if (0 > conn) {
    perror("Error from TRP Server accept()");
    goto cleanup;
  }

  /* establish a GSS context */
  if (trps_auth_connection(trps, conn, &gssctx)) {
    tr_notice("trps_accept: Error authorizing TID Server connection.");
    close(conn); /* did not work */
    conn=-1;
    goto cleanup;
  } 

  tr_notice("trps_accept: Connection authorized!");

    /* add this to the list of connections */
  trps_conn=trps_connection_new(tmp_ctx);
  if (trps_conn==NULL) {
    tr_debug("trps_handle_connection: Could not allocate TRPS connection.");
    close(conn);
    conn=-1;
    goto cleanup;
  }

  trps_err=trps_connection_set_add(trps->connections, trps_conn); /* handles talloc steal */
  if (trps_err != TRPS_ERR_OK) {
    tr_debug("trps_handle_connection: Error adding connection to set (trps_err=%d)", trps_err);
    close(conn);
    conn=-1;
    goto cleanup;
  }

  /* GSS context established, saved to the TRPS instance---success! */

cleanup:
  talloc_free(tmp_ctx);
  return conn;
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
