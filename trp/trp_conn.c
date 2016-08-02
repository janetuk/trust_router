#include <gsscon.h>
#include <gssapi.h>
#include <fcntl.h>
#include <talloc.h>
#include <unistd.h>

#include <tr_debug.h>
#include <trp_internal.h>

/* Threading note: mutex lock is only used for protecting get_status() and set_status().
 * If needed, locking for other operations (notably adding/removing connections) must be managed
 * by whomever is holding on to the connection list. */

int trp_connection_lock(TRP_CONNECTION *conn)
{
  return pthread_mutex_lock(&(conn->mutex));
}

int trp_connection_unlock(TRP_CONNECTION *conn)
{
  return pthread_mutex_unlock(&(conn->mutex));
}

int trp_connection_get_fd(TRP_CONNECTION *conn)
{
  return conn->fd;
}

void trp_connection_set_fd(TRP_CONNECTION *conn, int fd)
{
  conn->fd=fd;
}

/* we use the gss name of the peer to identify it */
static TRP_RC trp_connection_set_peer(TRP_CONNECTION *conn)
{
  OM_uint32 major_status=0;
  OM_uint32 minor_status=0;
  gss_name_t source_name=GSS_C_NO_NAME;
  gss_name_t target_name=GSS_C_NO_NAME;
  gss_buffer_desc peer_display_name={0,NULL};
  int local=0;

  tr_debug("gssctx = %p", trp_connection_get_gssctx(conn));
  tr_debug("*gssctx = %p", *trp_connection_get_gssctx(conn));
  major_status=gss_inquire_context(&minor_status,
                                   *trp_connection_get_gssctx(conn),
                                  &source_name,
                                  &target_name,
                                   NULL,
                                   NULL,
                                   NULL,
                                  &local,
                                   NULL);

  if (major_status != GSS_S_COMPLETE) {
    tr_err("trp_connection_set_peer: unable to identify GSS peer.");
    if (source_name!=GSS_C_NO_NAME)
      gss_release_name(&minor_status, &source_name);
    if (target_name!=GSS_C_NO_NAME)
      gss_release_name(&minor_status, &target_name);
    return TRP_ERROR;
  }

  if (local) {
    /* we are the source, peer is the target */
    major_status=gss_display_name(&minor_status, target_name, &peer_display_name, NULL);
  } else {
    /* we are the target, peer is the source */
    major_status=gss_display_name(&minor_status, source_name, &peer_display_name, NULL);
  }
  gss_release_name(&minor_status, &source_name);
  gss_release_name(&minor_status, &target_name);

  conn->peer=tr_new_name(peer_display_name.value);
  if (conn->peer==NULL)
    tr_err("trp_connection_set_peer: unable to allocate peer name.");
  else {
    if (conn->peer->len != peer_display_name.length) {
      tr_err("trp_connection_set_peer: error converting GSS display name to TR_NAME.");
      tr_free_name(conn->peer);
      conn->peer=NULL;
    }
  }
  gss_release_buffer(&minor_status, &peer_display_name);

  if (conn->peer==NULL)
    return TRP_ERROR;
  
  return TRP_SUCCESS;
}

TR_NAME *trp_connection_get_peer(TRP_CONNECTION *conn)
{
  return conn->peer;
}

TR_NAME *trp_connection_get_gssname(TRP_CONNECTION *conn)
{
  return conn->gssname;
}

void trp_connection_set_gssname(TRP_CONNECTION *conn, TR_NAME *gssname)
{
  conn->gssname=gssname;
}

gss_ctx_id_t *trp_connection_get_gssctx(TRP_CONNECTION *conn)
{
  return conn->gssctx;
}

void trp_connection_set_gssctx(TRP_CONNECTION *conn, gss_ctx_id_t *gssctx)
{
  conn->gssctx=gssctx;
}

TRP_CONNECTION_STATUS trp_connection_get_status(TRP_CONNECTION *conn)
{
  TRP_CONNECTION_STATUS status=TRP_CONNECTION_UNKNOWN;
  trp_connection_lock(conn);
  status=conn->status;
  trp_connection_unlock(conn);
  return status;
}

static void trp_connection_set_status(TRP_CONNECTION *conn, TRP_CONNECTION_STATUS status)
{
  TRP_CONNECTION_STATUS old_status=TRP_CONNECTION_UNKNOWN;
  trp_connection_lock(conn);
  old_status=conn->status;
  conn->status=status;
  trp_connection_unlock(conn);
  if ((status!=old_status) && (conn->status_change_cb!=NULL))
      conn->status_change_cb(conn, conn->status_change_cookie);
}

pthread_t *trp_connection_get_thread(TRP_CONNECTION *conn)
{
  return conn->thread;
}

void trp_connection_set_thread(TRP_CONNECTION *conn, pthread_t *thread)
{
  conn->thread=thread;
}

TRP_CONNECTION *trp_connection_get_next(TRP_CONNECTION *conn)
{
  return conn->next;
}

static void trp_connection_set_next(TRP_CONNECTION *conn, TRP_CONNECTION *next)
{
  conn->next=next;
}

/* Ok to call more than once; guarantees connection no longer in the list. Does not free removed element.
 * Returns handle to new list, you must replace your old handle on the list with this.  */
TRP_CONNECTION *trp_connection_remove(TRP_CONNECTION *conn, TRP_CONNECTION *remove)
{
  TRP_CONNECTION *cur=conn;
  TRP_CONNECTION *last=NULL;

  if (cur==NULL)
    return NULL;

  /* first element is a special case */
  if (cur==remove) {
    conn=trp_connection_get_next(cur); /* advance list head */
  } else {
    /* it was not the first element */
    last=cur;
    cur=trp_connection_get_next(cur);
    while (cur!=NULL) {
      if (cur==remove) {
        trp_connection_set_next(last, trp_connection_get_next(cur));
        break;
      }
      last=cur;
      cur=trp_connection_get_next(cur);
    }
  }
  return conn;
}

static TRP_CONNECTION *trp_connection_get_tail(TRP_CONNECTION *conn)
{
  while((conn!=NULL)&&(trp_connection_get_next(conn)!=NULL))
    conn=trp_connection_get_next(conn);
  return conn;
}

void trp_connection_append(TRP_CONNECTION *conn, TRP_CONNECTION *new)
{
  trp_connection_set_next(trp_connection_get_tail(conn), new);
}

static void trp_connection_mutex_init(TRP_CONNECTION *conn)
{
  pthread_mutex_init(&(conn->mutex), NULL);
}

/* talloc destructor for a connection: ensures connection is closed, memory freed */
static int trp_connection_destructor(void *object)
{
  TRP_CONNECTION *conn=talloc_get_type_abort(object, TRP_CONNECTION); /* aborts on wrong type */
  if ((trp_connection_get_status(conn)!=TRP_CONNECTION_CLOSED)
     && (trp_connection_get_fd(conn)!=-1))
    close(trp_connection_get_fd(conn));
  if (conn->peer!=NULL)
    tr_free_name(conn->peer);
  if (conn->gssname!=NULL)
    tr_free_name(conn->gssname);
  return 0;
}

TRP_CONNECTION *trp_connection_new(TALLOC_CTX *mem_ctx)
{
  TRP_CONNECTION *new_conn=talloc(mem_ctx, TRP_CONNECTION);
  gss_ctx_id_t *gssctx=NULL;
  pthread_t *thread=NULL;
  

  if (new_conn != NULL) {
    trp_connection_set_next(new_conn, NULL);
    trp_connection_set_fd(new_conn, -1);
    trp_connection_set_gssname(new_conn, NULL);
    trp_connection_mutex_init(new_conn);
    new_conn->peer=NULL; /* no true set function for this */
    new_conn->status_change_cb=NULL;
    new_conn->status_change_cookie=NULL;
    new_conn->status=TRP_CONNECTION_CLOSED;

    thread=talloc(new_conn, pthread_t);
    if (thread==NULL) {
      talloc_free(new_conn);
      return NULL;
    }
    trp_connection_set_thread(new_conn, thread);

    gssctx=talloc(new_conn, gss_ctx_id_t);
    if (gssctx==NULL) {
      talloc_free(new_conn);
      return NULL;
    }
    trp_connection_set_gssctx(new_conn, gssctx);
    talloc_set_destructor((void *)new_conn, trp_connection_destructor);
  }
  return new_conn;
}

void trp_connection_free(TRP_CONNECTION *conn)
{
  talloc_free(conn);
}

void trp_connection_close(TRP_CONNECTION *conn)
{
  close(trp_connection_get_fd(conn));
  trp_connection_set_fd(conn, -1);
  trp_connection_set_status(conn, TRP_CONNECTION_DOWN);
}

/* returns 0 on authorization success, 1 on failure, or -1 in case of error */
int trp_connection_auth(TRP_CONNECTION *conn, TRP_AUTH_FUNC auth_callback, void *callback_data)
{
  int rc = 0;
  int auth, autherr = 0;
  gss_buffer_desc nameBuffer = {0, NULL};
  gss_ctx_id_t *gssctx=trp_connection_get_gssctx(conn);

  nameBuffer.length = trp_connection_get_gssname(conn)->len;
  nameBuffer.value = tr_name_strdup(trp_connection_get_gssname(conn));

  tr_debug("trp_connection_auth: beginning passive authentication");
  if (trp_connection_get_status(conn)!=TRP_CONNECTION_AUTHORIZING)
    tr_warning("trp_connection_auth: warning: connection was not in TRP_CONNECTION_AUTHORIZING state.");

  rc = gsscon_passive_authenticate(trp_connection_get_fd(conn), nameBuffer, gssctx, auth_callback, callback_data);
  gss_release_buffer(NULL, &nameBuffer);
  if (rc!=0) {
    tr_debug("trp_connection_auth: Error from gsscon_passive_authenticate(), rc = 0x%08X.", rc);
    trp_connection_set_status(conn, TRP_CONNECTION_DOWN);
    return -1;
  }

  tr_debug("trp_connection_auth: beginning second stage authentication");
  if (rc = gsscon_authorize(*gssctx, &auth, &autherr)) {
    tr_debug("trp_connection_auth: Error from gsscon_authorize, rc = %d, autherr = %d.", 
             rc, autherr);
    trp_connection_set_status(conn, TRP_CONNECTION_DOWN);
    return -1;
  }

  trp_connection_set_peer(conn);
  trp_connection_set_status(conn, TRP_CONNECTION_UP);

  if (auth)
    tr_debug("trp_connection_auth: Connection authenticated, fd = %d.", trp_connection_get_fd(conn));
  else
    tr_debug("trp_connection_auth: Authentication failed, fd = %d.", trp_connection_get_fd(conn));

  return !auth;
}

/* Accept connection */
TRP_CONNECTION *trp_connection_accept(TALLOC_CTX *mem_ctx, int listen, TR_NAME *gssname)
{
  int conn_fd=-1;
  TRP_CONNECTION *conn=NULL;

  conn_fd = accept(listen, NULL, NULL);

  if (0 > conn_fd) {
    tr_notice("trp_connection_accept: accept() returned error.");
    return NULL;
  }
  conn=trp_connection_new(mem_ctx);
  trp_connection_set_fd(conn, conn_fd);
  trp_connection_set_gssname(conn, gssname);
  trp_connection_set_status(conn, TRP_CONNECTION_AUTHORIZING);
  return conn;
}

/* Initiate connection */
TRP_RC trp_connection_initiate(TRP_CONNECTION *conn, char *server, unsigned int port)
{
  int err = 0;
  int fd=-1;
  unsigned int use_port=0;

  if (0 == port)
    use_port = TRP_PORT;
  else 
    use_port = port;

  if (conn==NULL) {
    tr_err("trp_connection_initiate: null TRP_CONNECTION");
    return TRP_BADARG;
  }

  tr_debug("trp_connection_initiate: opening GSS connection to %s:%d",
           server,
           use_port);
  err = gsscon_connect(server,
                       use_port,
                       "trustrouter",
                      &fd,
                       trp_connection_get_gssctx(conn));
  if (err) {
    tr_debug("trp_connection_initiate: connection failed.");
    return TRP_ERROR;
  } else {
    tr_debug("trp_connection_initiate: connected.");
    trp_connection_set_fd(conn, fd);
    trp_connection_set_peer(conn);
    trp_connection_set_status(conn, TRP_CONNECTION_UP);
    return TRP_SUCCESS;
  }
}
