#include <pthread.h>
#include <fcntl.h>
#include <event2/event.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

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
struct trps_thread_data {
  TRP_CONNECTION *conn;
  TRPS_INSTANCE *trps;
};
/* thread to handle GSS connections to peers */
static void *tr_trps_thread(void *arg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct trps_thread_data *thread_data=talloc_get_type_abort(arg, struct trps_thread_data);
  TRP_CONNECTION *conn=thread_data->conn;
  TRPS_INSTANCE *trps=thread_data->trps;
  TR_MQ_MSG *msg=NULL;

  tr_debug("tr_trps_thread: started");
  trps_handle_connection(trps, conn);

  msg=tr_mq_msg_new(tmp_ctx, "trps_thread_exit");
  tr_mq_msg_set_payload(msg, (void *)conn, NULL); /* do not pass a free routine */
  if (msg==NULL)
    tr_err("tr_trps_thread: error allocating TR_MQ_MSG");
  else
    trps_mq_append(trps, msg);

  tr_debug("tr_trps_thread: exit");
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
  struct trps_thread_data *thread_data=NULL;

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
      thread_data=talloc(conn, struct trps_thread_data);
      if (thread_data==NULL) {
        tr_err("tr_trps_event_cb: unable to allocate trps_thread_data");
        talloc_free(tmp_ctx);
        return;
      }
      thread_data->conn=conn;
      thread_data->trps=trps;
      pthread_create(trp_connection_get_thread(conn), NULL, tr_trps_thread, thread_data);
      pthread_detach(*(trp_connection_get_thread(conn))); /* we will not rejoin the thread */
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

static void tr_trps_print_route_table(TRPS_INSTANCE *trps, FILE *f)
{
  char *table=trp_rtable_to_str(NULL, trps->rtable, " | ", NULL);
  if (table==NULL)
    fprintf(f, "Unable to print route table.\n");
  else {
    fprintf(f, "%s\n", table);
    talloc_free(table);
  }
}

static void tr_trps_process_mq(int socket, short event, void *arg)
{
  TRPS_INSTANCE *trps=talloc_get_type_abort(arg, TRPS_INSTANCE);
  TR_MQ_MSG *msg=NULL;
  const char *s=NULL;

  msg=trps_mq_pop(trps);
  while (msg!=NULL) {
    s=tr_mq_msg_get_message(msg);
    if (0==strcmp(s, "trps_thread_exit")) {
      tr_trps_cleanup_thread(trps,
                             talloc_get_type_abort(tr_mq_msg_get_payload(msg),
                                                   TRP_CONNECTION));
    }
    else if (0==strcmp(s, "tr_msg")) {
      if (trps_handle_tr_msg(trps, tr_mq_msg_get_payload(msg))!=TRP_SUCCESS)
        tr_notice("tr_trps_process_mq: error handling message.");
      else {
        tr_trps_print_route_table(trps, stderr);
      }
    }
    else
      tr_notice("tr_trps_process_mq: unknown message '%s' received.", tr_mq_msg_get_message(msg));

    tr_mq_msg_free(msg);
    msg=trps_mq_pop(trps);
  }
}

static void tr_trps_sweep(int listener, short event, void *arg)
{
  TRPS_INSTANCE *trps=talloc_get_type_abort(arg, TRPS_INSTANCE);
  tr_debug("tr_trps_sweep: sweeping routes");
  trps_sweep_routes(trps);
}

static int tr_trps_events_destructor(void *obj)
{
  TR_TRPS_EVENTS *ev=talloc_get_type_abort(obj, TR_TRPS_EVENTS);
  if (ev->mq_ev!=NULL)
    event_free(ev->mq_ev);
  if (ev->sweep_ev!=NULL)
    event_free(ev->sweep_ev);
  return 0;
}
TR_TRPS_EVENTS *tr_trps_events_new(TALLOC_CTX *mem_ctx)
{
  TR_TRPS_EVENTS *ev=talloc(mem_ctx, TR_TRPS_EVENTS);
  if (ev!=NULL) {
    ev->listen_ev=talloc(ev, struct tr_socket_event);
    ev->mq_ev=NULL;
    ev->sweep_ev=NULL;
    if (ev->listen_ev==NULL) {
      talloc_free(ev);
      ev=NULL;
    }
    talloc_set_destructor((void *)ev, tr_trps_events_destructor);
  }
  return ev;
}

/* Configure the trps instance and set up its event handler.
 * Fills in trps_ev, which should be allocated by caller. */
TRP_RC tr_trps_event_init(struct event_base *base,
                       TRPS_INSTANCE *trps,
                       TR_CFG_MGR *cfg_mgr,
                       TR_TRPS_EVENTS *trps_ev)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_socket_event *listen_ev=NULL;
  struct tr_trps_event_cookie *cookie;
  struct timeval two_secs={2, 0};
  TRP_RC retval=TRP_ERROR;

  if (trps_ev == NULL) {
    tr_debug("tr_trps_event_init: Null trps_ev.");
    retval=TRP_BADARG;
    goto cleanup;
  }

  /* get convenient handles */
  listen_ev=trps_ev->listen_ev;

  /* Create the cookie for callbacks. It is part of the trps context, so it will
   * be cleaned up when trps is freed by talloc_free. */
  cookie=talloc(tmp_ctx, struct tr_trps_event_cookie);
  if (cookie == NULL) {
    tr_debug("tr_trps_event_init: Unable to allocate cookie.");
    retval=TRP_NOMEM;
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
    retval=TRP_ERROR;
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

  /* now set up the route table sweep timer event */
  trps_ev->sweep_ev=event_new(base, -1, EV_TIMEOUT|EV_PERSIST, tr_trps_sweep, (void *)trps);
  /* todo: event_add(trps_ev->sweep_ev, &(cfg_mgr->active->internal->route_sweep_interval)); */
  event_add(trps_ev->sweep_ev, &two_secs);

  retval=TRP_SUCCESS;

cleanup:
  talloc_free(tmp_ctx);
  return retval;
}


struct trpc_notify_cb_data {
  int msg_ready;
  pthread_cond_t cond;
  pthread_mutex_t mutex;
};

static void tr_trpc_mq_cb(TR_MQ *mq, void *arg)
{
  struct trpc_notify_cb_data *cb_data=(struct trpc_notify_cb_data *) arg;
  pthread_mutex_lock(&(cb_data->mutex));
  if (!cb_data->msg_ready) {
    cb_data->msg_ready=1;
    pthread_cond_signal(&(cb_data->cond));
  }
  pthread_mutex_unlock(&(cb_data->mutex));
}

/* data passed to thread */
struct trpc_thread_data {
  TRPC_INSTANCE *trpc;
  TRPS_INSTANCE *trps;
};
static void *tr_trpc_thread(void *arg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct trpc_thread_data *thread_data=talloc_get_type_abort(arg, struct trpc_thread_data);
  TRPC_INSTANCE *trpc=thread_data->trpc;
  TRPS_INSTANCE *trps=thread_data->trps;
  TRP_RC rc=TRP_ERROR;
  TR_MQ_MSG *msg=NULL;
  const char *msg_type=NULL;
  char *encoded_msg=NULL;

  struct trpc_notify_cb_data cb_data={0,
                                      PTHREAD_COND_INITIALIZER,
                                      PTHREAD_MUTEX_INITIALIZER};

  tr_debug("tr_trpc_thread: started");

  /* set up the mq for receiving */
  pthread_mutex_lock(&(cb_data.mutex)); /* hold this lock until we enter the main loop */

  tr_mq_lock(trpc->mq);
  tr_mq_set_notify_cb(trpc->mq, tr_trpc_mq_cb, (void *) &cb_data);
  tr_mq_unlock(trpc->mq);

  rc=trpc_connect(trpc);
  if (rc!=TRP_SUCCESS) {
    tr_notice("tr_trpc_thread: failed to initiate connection to %s:%d.",
              trpc_get_server(trpc),
              trpc_get_port(trpc));
  } else {
    while (1) {
      cb_data.msg_ready=0;
      pthread_cond_wait(&(cb_data.cond), &(cb_data.mutex));
      /* verify the condition */
      if (cb_data.msg_ready) {
        msg=trpc_mq_pop(trpc);
        if (msg==NULL) {
          /* no message in the queue */
          tr_err("tr_trpc_thread: notified of msg, but queue empty");
          break;
        }

        msg_type=tr_mq_msg_get_message(msg);

        if (0==strcmp(msg_type, "trpc_abort")) {
          tr_mq_msg_free(msg);
          break; /* exit loop */
        }
        else if (0==strcmp(msg_type, "trpc_send")) {
          encoded_msg=tr_mq_msg_get_payload(msg);
          if (encoded_msg==NULL)
            tr_notice("tr_trpc_thread: null outgoing TRP message.");
          else {
            rc = trpc_send_msg(trpc, encoded_msg);
            if (rc!=TRP_SUCCESS) {
              tr_notice("tr_trpc_thread: trpc_send_msg failed.");
              tr_mq_msg_free(msg);
              break;
            }
          }
        }
        else
          tr_notice("tr_trpc_thread: unknown message '%s' received.", msg_type);

        tr_mq_msg_free(msg);
      }
    }
  }

  msg=tr_mq_msg_new(tmp_ctx, "trpc_thread_exit");
  tr_mq_msg_set_payload(msg, (void *)trpc, NULL); /* do not pass a free routine */
  if (msg==NULL)
    tr_err("tr_trpc_thread: error allocating TR_MQ_MSG");
  else
    trps_mq_append(trps, msg);

  talloc_free(tmp_ctx);
  return NULL;
}

/* starts a trpc thread to connect to server:port */
TRPC_INSTANCE *tr_trpc_initiate(TRPS_INSTANCE *trps, const char *server, unsigned int port)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRPC_INSTANCE *trpc=NULL;
  TRP_CONNECTION *conn=NULL;
  struct trpc_thread_data *thread_data=NULL;

  tr_debug("tr_trpc_initiate entered");
  trpc=trpc_new(tmp_ctx);
  if (trpc==NULL) {
    tr_crit("tr_trpc_initiate: could not allocate TRPC_INSTANCE.");
    goto cleanup;
  }
  tr_debug("tr_trpc_initiate: allocated trpc");

  conn=trp_connection_new(trpc);
  if (conn==NULL) {
    tr_crit("tr_trpc_initiate: could not allocate TRP_CONNECTION.");
    goto cleanup;
  }
  trpc_set_conn(trpc, conn);
  trpc_set_server(trpc, talloc_strdup(trpc, server));
  trpc_set_port(trpc, port);
  tr_debug("tr_trpc_initiate: allocated connection");
  
  /* start thread */
  thread_data=talloc(trpc, struct trpc_thread_data);
  if (thread_data==NULL) {
    tr_crit("tr_trpc_initiate: could not allocate struct trpc_thread_data.");
    goto cleanup;
  }
  thread_data->trpc=trpc;
  thread_data->trps=trps;

  pthread_create(trp_connection_get_thread(conn), NULL, tr_trpc_thread, thread_data);
  pthread_detach(*(trp_connection_get_thread(conn))); /* we will not rejoin the thread */

  tr_debug("tr_trpc_initiate: started trpc thread");
  trps_add_trpc(trps, trpc);

  talloc_report_full(trps, stderr);
  talloc_report_full(tmp_ctx, stderr);

 cleanup:
  talloc_free(tmp_ctx);
  return trpc;
}