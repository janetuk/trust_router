#include <pthread.h>
#include <fcntl.h>
#include <event2/event.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>

#include <gsscon.h>
#include <tr_rp.h>
#include <trp_internal.h>
#include <tr_config.h>
#include <tr_event.h>
#include <tr_debug.h>
#include <tr_trp.h>

/* hold a trps instance and a config manager */
struct tr_trps_event_cookie {
  TRPS_INSTANCE *trps;
  TR_CFG_MGR *cfg_mgr;
};


static int tr_trps_req_handler (TRPS_INSTANCE *trps,
                                TRP_REQ *orig_req, 
                                void *tr_in)
{
  if (orig_req != NULL) 
    free(orig_req);
  return -1; /* not handling anything right now */
}


static int tr_trps_gss_handler(gss_name_t client_name, gss_buffer_t gss_name,
                               void *cookie_in)
{
  TR_RP_CLIENT *rp;
  struct tr_trps_event_cookie *cookie=(struct tr_trps_event_cookie *)cookie_in;
  TRPS_INSTANCE *trps = cookie->trps;
  TR_CFG_MGR *cfg_mgr = cookie->cfg_mgr;
  TR_NAME name={gss_name->value, gss_name->length};

  tr_debug("tr_trps_gss_handler()");

  if ((!client_name) || (!gss_name) || (!trps) || (!cfg_mgr)) {
    tr_debug("tr_trps_gss_handler: Bad parameters.");
    return -1;
  }
  
  /* look up the RP client matching the GSS name */
  if ((NULL == (rp = tr_rp_client_lookup(cfg_mgr->active->rp_clients, &name)))) {
    tr_debug("tr_trps_gss_handler: Unknown GSS name %.*s", name.len, name.buf);
    return -1;
  }

  /*trps->rp_gss = rp;*/
  tr_debug("Client's GSS Name: %.*s", name.len, name.buf);

  return 0;
}


/* data passed to thread */
struct thread_data {
  TRP_CONNECTION *conn;
  TRPS_INSTANCE *trps;
};
/* thread to handle GSS connections to peers */
static void *tr_trps_conn_thread(void *arg)
{
  struct thread_data *thread_data=talloc_get_type_abort(arg, struct thread_data);
  TRP_CONNECTION *conn=thread_data->conn;
  TRPS_INSTANCE *trps=thread_data->trps;

  tr_debug("tr_trps_conn_thread: started");
  /* try to establish a GSS context */
  if (0!=trp_connection_auth(conn, trps->auth_handler, trps->cookie)) {
    tr_notice("tr_trps_conn_thread: failed to authorize connection");
    pthread_exit(NULL);
  }
  tr_notice("tr_trps_conn_thread: authorized connection");
  return NULL;
}

/* called when a connection to the TRPS port is received */
static void tr_trps_event_cb(int listener, short event, void *arg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRPS_INSTANCE *trps = talloc_get_type_abort(arg, TRPS_INSTANCE); /* aborts on wrong type */
  TRP_CONNECTION *conn=NULL;
  TR_NAME *gssname=NULL;
  char *name=NULL;
  struct thread_data *thread_data;

  if (0==(event & EV_READ)) {
    tr_debug("tr_trps_event_cb: unexpected event on TRPS socket (event=0x%X)", event);
  } else {
    /* create a thread to handle this connection */
    asprintf(&name, "trustrouter@%s", trps->hostname);
    gssname=tr_new_name(name);
    free(name); name=NULL;
    conn=trp_connection_accept(tmp_ctx, listener, gssname, trps_auth_cb, NULL, trps);
    if (conn!=NULL) {
      /* need to monitor this fd and trigger events when read becomes possible */
      thread_data=talloc(conn, struct thread_data);
      if (thread_data==NULL) {
        tr_err("tr_trps_event_cb: unable to allocate thread_data");
        talloc_free(tmp_ctx);
        return;
      }
      thread_data->conn=conn;
      thread_data->trps=trps;
      pthread_create(conn->thread, NULL, tr_trps_conn_thread, thread_data);
      trps_add_connection(trps, conn); /* remember the connection */
    }
  }
  talloc_free(tmp_ctx);
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

