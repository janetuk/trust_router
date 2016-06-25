#include <pthread.h>
#include <fcntl.h>
#include <event2/event.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <gsscon.h>
#include <tr_rp.h>
#include <trp_internal.h>
#include <tr_config.h>
#include <tr_event.h>
#include <tr_msg.h>
#include <tr_trp.h>
#include <tr_debug.h>

/* hold a trps instance and a config manager */
struct tr_trps_event_cookie {
  TRPS_INSTANCE *trps;
  TR_CFG_MGR *cfg_mgr;
};


/* callback to schedule event to process messages */
static void tr_trps_mq_cb(TR_MQ *mq, void *arg)
{
  struct event *mq_ev=(struct event *)arg;
  event_active(mq_ev, 0, 0);
}

static void msg_free_helper(void *p)
{
  tr_msg_free_decoded((TR_MSG *)p);
}
/* takes a TR_MSG and puts it in a TR_MQ_MSG for processing by the main thread */
static TRP_RC tr_trps_msg_handler(TRPS_INSTANCE *trps,
                                  TRP_CONNECTION *conn,
                                  TR_MSG *tr_msg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_MQ_MSG *mq_msg=NULL;

  /* n.b., conn is available here, but do not hold onto the reference
   * because it may be cleaned up if the originating connection goes
   * down before the message is processed */
  mq_msg=tr_mq_msg_new(tmp_ctx, "tr_msg");
  if (mq_msg==NULL) {
    return TRP_NOMEM;
  }
  tr_mq_msg_set_payload(mq_msg, (void *)tr_msg, msg_free_helper);
  trps_mq_append(trps, mq_msg);
  talloc_free(tmp_ctx); /* cleans up the message if it did not get appended correctly */
  return TRP_SUCCESS;
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
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct thread_data *thread_data=talloc_get_type_abort(arg, struct thread_data);
  TRP_CONNECTION *conn=thread_data->conn;
  TRPS_INSTANCE *trps=thread_data->trps;
  TR_MQ_MSG *msg=NULL;

  tr_debug("tr_trps_conn_thread: started");
  trps_handle_connection(trps, conn);

  msg=tr_mq_msg_new(tmp_ctx, "thread_exit");
  tr_mq_msg_set_payload(msg, (void *)conn, NULL); /* do not pass a free routine */
  if (msg==NULL)
    tr_err("tr_trps_conn_thread: error allocating TR_MQ_MSG");
  else
    trps_mq_append(trps, msg);

  tr_debug("tr_trps_conn_thread: exit");
  talloc_free(tmp_ctx);
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
    conn=trp_connection_accept(tmp_ctx, listener, gssname);
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
      pthread_detach(*(conn->thread)); /* we will not rejoin the thread */
      trps_add_connection(trps, conn); /* remember the connection */
    }
  }
  talloc_free(tmp_ctx);
}

static void tr_trps_cleanup_thread(TRPS_INSTANCE *trps, TRP_CONNECTION *conn)
{
  /* everything belonging to the thread is in the TRP_CONNECTION
   * associated with it */
  trps_remove_connection(trps, conn);
  tr_debug("Deleted connection");
}

static void tr_trps_process_mq(int socket, short event, void *arg)
{
  TRPS_INSTANCE *trps=talloc_get_type_abort(arg, TRPS_INSTANCE);
  TR_MQ_MSG *msg=NULL;
  const char *s=NULL;
  char *tmp=NULL;

  tr_debug("tr_trps_process_mw: starting");
  msg=trps_mq_pop(trps);
  while (msg!=NULL) {
    s=tr_mq_msg_get_message(msg);
    if (0==strcmp(s, "thread_exit")) {
      tr_trps_cleanup_thread(trps,
                             talloc_get_type_abort(tr_mq_msg_get_payload(msg),
                                                   TRP_CONNECTION));
    }
    else if (0==strcmp(s, "tr_msg")) {
      tmp=tr_msg_encode(tr_mq_msg_get_payload(msg));
      tr_debug("tr_msg: %s", tmp);
      tr_msg_free_encoded(tmp);
    }
    else
      tr_notice("tr_trps_process_mq: unknown message '%s' received.", tr_mq_msg_get_message(msg));

    tr_mq_msg_free(msg);
    msg=trps_mq_pop(trps);
  }
  tr_debug("tr_trps_process_mw: ending");
}

static int tr_trps_events_destructor(void *obj)
{
  TR_TRPS_EVENTS *ev=talloc_get_type_abort(obj, TR_TRPS_EVENTS);
  if (ev->mq_ev!=NULL)
    event_free(ev->mq_ev);
  return 0;
}
TR_TRPS_EVENTS *tr_trps_events_new(TALLOC_CTX *mem_ctx)
{
  TR_TRPS_EVENTS *ev=talloc(mem_ctx, TR_TRPS_EVENTS);
  if (ev!=NULL) {
    ev->listen_ev=talloc(ev, struct tr_socket_event);
    ev->mq_ev=NULL;
    if (ev->listen_ev==NULL) {
      talloc_free(ev);
      ev=NULL;
    }
    talloc_set_destructor((void *)ev, tr_trps_events_destructor);
  }
  return ev;
}

/* Configure the trps instance and set up its event handler.
 * Returns 0 on success, nonzero on failure. Results in 
 * trps_ev, which should be allocated by caller. */
int tr_trps_event_init(struct event_base *base,
                       TRPS_INSTANCE *trps,
                       TR_CFG_MGR *cfg_mgr,
                       TR_TRPS_EVENTS *trps_ev)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_socket_event *listen_ev=NULL;
  struct tr_trps_event_cookie *cookie;
  int retval=0;

  if (trps_ev == NULL) {
    tr_debug("tr_trps_event_init: Null trps_ev.");
    retval=1;
    goto cleanup;
  }

  /* get convenient handles */
  listen_ev=trps_ev->listen_ev;

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
  listen_ev->sock_fd=trps_get_listener(trps,
                                       tr_trps_msg_handler,
                                       tr_trps_gss_handler,
                                       cfg_mgr->active->internal->hostname,
                                       cfg_mgr->active->internal->trps_port,
                                       (void *)cookie);
  if (listen_ev->sock_fd < 0) {
    tr_crit("Error opening TRP server socket.");
    retval=1;
    goto cleanup;
  }
  
  /* and its event */
  listen_ev->ev=event_new(base,
                          listen_ev->sock_fd,
                          EV_READ|EV_PERSIST,
                          tr_trps_event_cb,
                          (void *)trps);
  event_add(listen_ev->ev, NULL);
  
  /* now set up message queue processing event, only triggered by
   * tr_trps_mq_cb() */
  trps_ev->mq_ev=event_new(base,
                           0,
                           EV_PERSIST,
                           tr_trps_process_mq,
                           (void *)trps);
  tr_mq_set_notify_cb(trps->mq, tr_trps_mq_cb, trps_ev->mq_ev);

cleanup:
  talloc_free(tmp_ctx);
  return retval;
}

