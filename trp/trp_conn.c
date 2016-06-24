#include <gsscon.h>
#include <fcntl.h>
#include <talloc.h>
#include <unistd.h>

#include <tr_debug.h>
#include <trp_internal.h>

int trp_connection_get_fd(TRP_CONNECTION *conn)
{
  return conn->fd;
}

void trp_connection_set_fd(TRP_CONNECTION *conn, int fd)
{
  conn->fd=fd;
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
  TRP_CONNECTION_STATUS status;
  pthread_mutex_lock(&(conn->status_mutex));
  status=conn->status;
  pthread_mutex_unlock(&(conn->status_mutex));
  return status;
}

void trp_connection_set_status(TRP_CONNECTION *conn, TRP_CONNECTION_STATUS status)
{
  pthread_mutex_lock(&(conn->status_mutex));
  conn->status=status;
  pthread_mutex_unlock(&(conn->status_mutex));
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
  pthread_mutex_init(&(conn->status_mutex), NULL);
}

/* talloc destructor for a connection: ensures connection is closed, memory freed */
static int trp_connection_destructor(void *object)
{
  TRP_CONNECTION *conn=talloc_get_type_abort(object, TRP_CONNECTION); /* aborts on wrong type */
  if ((trp_connection_get_status(conn)!=TRP_CONNECTION_DOWN)
     && (trp_connection_get_fd(conn)!=-1))
    close(trp_connection_get_fd(conn));
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
    trp_connection_set_gssctx(new_conn, NULL);
    trp_connection_mutex_init(new_conn);
    trp_connection_set_status(new_conn, TRP_CONNECTION_DOWN);
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
  /* TODO: shut down connection if it is still open */
  talloc_free(conn);
}


/* returns 0 on authorization success, 1 on failure, or -1 in case of error */
int trp_connection_auth(TRP_CONNECTION *conn, TRP_AUTH_FUNC auth_callback, void *callback_data)
{
  int rc = 0;
  int auth, autherr = 0;
  gss_buffer_desc nameBuffer = {0, NULL};
  gss_ctx_id_t gssctx;

  /* TODO: shouldn't really peek into TR_NAME... */
  nameBuffer.length = trp_connection_get_gssname(conn)->len;
  nameBuffer.value = trp_connection_get_gssname(conn)->buf;

  tr_debug("trp_connection_auth: beginning passive authentication");
  if (rc = gsscon_passive_authenticate(trp_connection_get_fd(conn), nameBuffer, &gssctx, auth_callback, callback_data)) {
    tr_debug("trp_connection_auth: Error from gsscon_passive_authenticate(), rc = 0x%08X.", rc);
    return -1;
  }

  tr_debug("trp_connection_auth: beginning second stage authentication");
  if (rc = gsscon_authorize(gssctx, &auth, &autherr)) {
    tr_debug("trp_connection_auth: Error from gsscon_authorize, rc = %d, autherr = %d.", 
             rc, autherr);
    return -1;
  }

  if (auth)
    tr_debug("trp_connection_auth: Connection authenticated, fd = %d.", trp_connection_get_fd(conn));
  else
    tr_debug("trp_connection_auth: Authentication failed, fd = %d.", trp_connection_get_fd(conn));

  return !auth;
}

/* Accept connection */
TRP_CONNECTION *trp_connection_accept(TALLOC_CTX *mem_ctx, int listen, TR_NAME *gssname, TRP_AUTH_FUNC auth_handler, TRP_REQ_FUNC req_handler,
                                      void *cookie)
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
  return conn;
}

