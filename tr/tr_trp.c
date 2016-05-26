#include <fcntl.h>
#include <event2/event.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>

#include <gsscon.h>
#include <tr_rp.h>
#include <tr_config.h>
#include <tr_event.h>
#include <tr_debug.h>
#include <tr_trp.h>

/* hold a trps instance and a config manager */
struct tr_trps_event_cookie {
  TRPS_INSTANCE *trps;
  TR_CFG_MGR *cfg_mgr;
};


/********** Ersatz TRPS implementation **********/
TRPS_INSTANCE *trps_create (TALLOC_CTX *mem_ctx)
{
  return talloc_zero(mem_ctx, TRPS_INSTANCE);
}

void trps_destroy (TRPS_INSTANCE *trps)
{
  if (trps)
    talloc_free(trps);
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

#if 0

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
#endif

static int tr_trps_req_handler (TRPS_INSTANCE *trps,
                                TRP_REQ *orig_req, 
                                TRP_RESP *resp,
                                void *tr_in)
{
  if (orig_req != NULL) 
    free(orig_req);
  return -1; /* not handling anything right now */
}

static void trps_handle_connection (TRPS_INSTANCE *trps, int conn)
{
  return;
}

static int tr_trps_gss_handler(gss_name_t client_name, TR_NAME *gss_name,
                               void *cookie_in)
{
  TR_RP_CLIENT *rp;
  struct tr_trps_event_cookie *cookie=(struct tr_trps_event_cookie *)cookie_in;
  TRPS_INSTANCE *trps = cookie->trps;
  TR_CFG_MGR *cfg_mgr = cookie->cfg_mgr;

  tr_debug("tr_trps_gss_handler()");

  if ((!client_name) || (!gss_name) || (!trps) || (!cfg_mgr)) {
    tr_debug("tr_trps_gss_handler: Bad parameters.");
    return -1;
  }
  
  /* look up the RP client matching the GSS name */
  if ((NULL == (rp = tr_rp_client_lookup(cfg_mgr->active->rp_clients, gss_name)))) {
    tr_debug("tr_trps_gss_handler: Unknown GSS name %s", gss_name->buf);
    return -1;
  }

  trps->rp_gss = rp;
  tr_debug("Client's GSS Name: %s", gss_name->buf);

  return 0;
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


/* Accept and process a connection on a port opened with trps_get_listener() */
int trps_accept(TRPS_INSTANCE *trps, int listen)
{
  int conn=-1;

  conn = accept(listen, NULL, NULL);

  if (0 > conn) {
    perror("Error from TRP Server accept()");
    return 1;
  }

  /* does not fork, handles request in main process */
  trps_handle_connection(trps, conn);
  write(conn, "TRP Online\n", strlen("TRP Online\n"));
  close(conn);
  return 0;
}


/********** Event Handling **********/

/* called when a connection to the TRPS port is received */
static void tr_trps_event_cb(int listener, short event, void *arg)
{
  TRPS_INSTANCE *trps = (TRPS_INSTANCE *)arg;

  if (0==(event & EV_READ))
    tr_debug("tr_trps_event_cb: unexpected event on TRPS socket (event=0x%X)", event);
  else 
    trps_accept(trps, listener);
}


/* Configure the trps instance and set up its event handler.
 * Returns 0 on success, nonzero on failure. Fills in
 * *trps_event (which should be allocated by caller). */
int tr_trps_event_init(struct event_base *base,
                       TRPS_INSTANCE *trps,
                       TR_CFG_MGR *cfg_mgr,
                       struct tr_socket_event *trps_ev)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_trps_event_cookie *cookie;
  int retval=0;

  if (trps_ev == NULL) {
    tr_debug("tr_trps_event_init: Null trps_ev.");
    retval=1;
    goto cleanup;
  }

  /* Create the cookie for callbacks. It is part of the trps context, so it will
   * be cleaned up when trps is freed by talloc_free. */
  cookie=talloc(tmp_ctx, struct tr_trps_event_cookie);
  if (cookie == NULL) {
    tr_debug("tr_trps_event_init: Unable to allocate cookie.");
    retval=1;
    goto cleanup;
  }
  cookie->trps=trps;
  cookie->cfg_mgr=cfg_mgr;
  talloc_steal(trps, cookie);

  /* get a trps listener */
  trps_ev->sock_fd=trps_get_listener(trps,
                                     tr_trps_req_handler,
                                     tr_trps_gss_handler,
                                     cfg_mgr->active->internal->hostname,
                                     cfg_mgr->active->internal->trps_port,
                                     (void *)cookie);
  if (trps_ev->sock_fd < 0) {
    tr_crit("Error opening TRP server socket.");
    retval=1;
    goto cleanup;
  }

  /* and its event */
  trps_ev->ev=event_new(base,
                        trps_ev->sock_fd,
                        EV_READ|EV_PERSIST,
                        tr_trps_event_cb,
                        (void *)trps);
  event_add(trps_ev->ev, NULL);

cleanup:
  talloc_free(tmp_ctx);
  return retval;
}
