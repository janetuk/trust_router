#include <stdio.h>  /* TODO: remove this --jlr */
#include <pthread.h>
#include <fcntl.h>
#include <event2/event.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <gsscon.h>
#include <tr.h>
#include <tr_mq.h>
#include <tr_rp.h>
#include <trp_internal.h>
#include <trp_ptable.h>
#include <trp_rtable.h>
#include <tr_config.h>
#include <tr_event.h>
#include <tr_msg.h>
#include <tr_trp.h>
#include <tr_debug.h>

/* data for event callbacks */
struct tr_trps_event_cookie {
  TRPS_INSTANCE *trps;
  TR_CFG_MGR *cfg_mgr;
  struct event *ev;
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

static void tr_free_name_helper(void *arg)
{
  tr_free_name((TR_NAME *)arg);
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
  mq_msg=tr_mq_msg_new(tmp_ctx, TR_MQMSG_MSG_RECEIVED, TR_MQ_PRIO_NORMAL);
  if (mq_msg==NULL) {
    return TRP_NOMEM;
  }
  tr_mq_msg_set_payload(mq_msg, (void *)tr_msg, msg_free_helper);
  trps_mq_add(trps, mq_msg);
  talloc_free(tmp_ctx); /* cleans up the message if it did not get appended correctly */
  return TRP_SUCCESS;
}


static int tr_trps_gss_handler(gss_name_t client_name, gss_buffer_t gss_name,
                               void *cookie_in)
{
  struct tr_trps_event_cookie *cookie=(struct tr_trps_event_cookie *)cookie_in;
  TRPS_INSTANCE *trps = cookie->trps;
  TR_CFG_MGR *cfg_mgr = cookie->cfg_mgr;
  TR_NAME name={gss_name->value, gss_name->length};

  tr_debug("tr_trps_gss_handler()");

  if ((!client_name) || (!gss_name) || (!trps) || (!cfg_mgr)) {
    tr_debug("tr_trps_gss_handler: Bad parameters.");
    return -1;
  }
  
  /* look up the TRPS peer matching the GSS name */
  if (NULL==trps_get_peer_by_gssname(trps, &name)) {
    tr_warning("tr_trps_gss_handler: Connection attempt from unknown peer (GSS name: %.*s).", name.len, name.buf);
    return -1;
  }

  tr_debug("Client's GSS Name: %.*s", name.len, name.buf);
  return 0;
}

/* data passed to thread */
struct trps_thread_data {
  TRP_CONNECTION *conn;
  TRPS_INSTANCE *trps;
};
/* thread to handle GSS connections from peers */
static void *tr_trps_thread(void *arg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct trps_thread_data *thread_data=talloc_get_type_abort(arg, struct trps_thread_data);
  TRP_CONNECTION *conn=thread_data->conn;
  TRPS_INSTANCE *trps=thread_data->trps;
  TR_MQ_MSG *msg=NULL;

  tr_debug("tr_trps_thread: started");
  if (trps_authorize_connection(trps, conn)!=TRP_SUCCESS)
    goto cleanup;

  msg=tr_mq_msg_new(tmp_ctx, TR_MQMSG_TRPS_CONNECTED, TR_MQ_PRIO_HIGH);
  tr_mq_msg_set_payload(msg, (void *)tr_dup_name(trp_connection_get_peer(conn)), tr_free_name_helper);
  if (msg==NULL) {
    tr_err("tr_trps_thread: error allocating TR_MQ_MSG");
    goto cleanup;
  } 
  trps_mq_add(trps, msg); /* steals msg context */
  msg=NULL;

  trps_handle_connection(trps, conn);

cleanup:
  msg=tr_mq_msg_new(tmp_ctx, TR_MQMSG_TRPS_DISCONNECTED, TR_MQ_PRIO_HIGH);
  tr_mq_msg_set_payload(msg, (void *)conn, NULL); /* do not pass a free routine */
  if (msg==NULL)
    tr_err("tr_trps_thread: error allocating TR_MQ_MSG");
  else
    trps_mq_add(trps, msg);
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
      trps_add_connection(trps, conn); /* remember the connection */
      pthread_create(trp_connection_get_thread(conn), NULL, tr_trps_thread, thread_data);
    }
  }
  talloc_free(tmp_ctx);
}

static void tr_trps_cleanup_conn(TRPS_INSTANCE *trps, TRP_CONNECTION *conn)
{
  /* everything belonging to the thread is in the TRP_CONNECTION
   * associated with it */
  tr_debug("tr_trps_cleanup_conn: freeing %p", conn);
/*  pthread_join(*trp_connection_get_thread(conn), NULL); -- removed while debugging, put back!!! --jlr */
  trps_remove_connection(trps, conn);
  talloc_report_full(conn, stderr);
  trp_connection_free(conn);
  tr_debug("tr_trps_cleanup_conn: deleted connection");
}

static void tr_trps_cleanup_trpc(TRPS_INSTANCE *trps, TRPC_INSTANCE *trpc)
{
  pthread_join(*trp_connection_get_thread(trpc_get_conn(trpc)), NULL);
  trps_remove_trpc(trps, trpc);
  trpc_free(trpc);
  tr_debug("tr_trps_cleanup_trpc: deleted connection");
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

  talloc_report_full(trps->mq, stderr);
  msg=trps_mq_pop(trps);
  while (msg!=NULL) {
    s=tr_mq_msg_get_message(msg);
    if (0==strcmp(s, TR_MQMSG_TRPS_CONNECTED)) {
      TR_NAME *gssname=(TR_NAME *)tr_mq_msg_get_payload(msg);
      TRP_PEER *peer=trps_get_peer_by_gssname(trps, gssname);
      if (peer==NULL)
        tr_err("tr_trps_process_mq: incoming connection to unknown peer (%s) reported.", gssname->buf);
      else {
        trp_peer_set_incoming_status(peer, PEER_CONNECTED);
        tr_err("tr_trps_process_mq: incoming connection to %s established.", gssname->buf);
      }
    }
    else if (0==strcmp(s, TR_MQMSG_TRPS_DISCONNECTED)) {
      TRP_CONNECTION *conn=talloc_get_type_abort(tr_mq_msg_get_payload(msg), TRP_CONNECTION);
      TR_NAME *gssname=trp_connection_get_gssname(conn);
      TRP_PEER *peer=trps_get_peer_by_gssname(trps, gssname);
      if (peer==NULL) {
        tr_err("tr_trps_process_mq: disconnection of unknown peer (%s) reported.",
               trp_connection_get_gssname(conn)->buf);
      } else {
        trp_peer_set_incoming_status(peer, PEER_DISCONNECTED);
        tr_trps_cleanup_conn(trps, conn);
        tr_err("tr_trps_process_mq: incoming connection to %s lost.", gssname->buf);
      }
    }
    else if (0==strcmp(s, TR_MQMSG_TRPC_CONNECTED)) {
      TR_NAME *svcname=(TR_NAME *)tr_mq_msg_get_payload(msg);
      TRP_PEER *peer=trps_get_peer_by_servicename(trps, svcname);
      if (peer==NULL)
        tr_err("tr_trps_process_mq: connection to unknown peer (%s) reported.", svcname->buf);
      else {
        trp_peer_set_outgoing_status(peer, PEER_CONNECTED);
        tr_err("tr_trps_process_mq: outgoing connection to %s established.", svcname->buf);
      }
    }
    else if (0==strcmp(s, TR_MQMSG_TRPC_DISCONNECTED)) {
      /* trpc connection died */
      TRPC_INSTANCE *trpc=talloc_get_type_abort(tr_mq_msg_get_payload(msg), TRPC_INSTANCE);
      TR_NAME *gssname=trpc_get_gssname(trpc);
      TRP_PEER *peer=trps_get_peer_by_gssname(trps, gssname);
      if (peer==NULL)
        tr_err("tr_trps_process_mq: disconnection of unknown peer (%s) reported.", gssname->buf);
      else {
        trp_peer_set_outgoing_status(peer, PEER_DISCONNECTED);
        tr_err("tr_trps_process_mq: outgoing connection to %s lost.", gssname->buf);
        tr_trps_cleanup_trpc(trps, trpc);
      }
    }

    else if (0==strcmp(s, TR_MQMSG_MSG_RECEIVED)) {
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

static void tr_trps_update(int listener, short event, void *arg)
{
  struct tr_trps_event_cookie *cookie=talloc_get_type_abort(arg, struct tr_trps_event_cookie);
  TRPS_INSTANCE *trps=cookie->trps;
  struct event *ev=cookie->ev;

  tr_debug("tr_trps_update: sending scheduled route updates.");
  trps_update(trps, TRP_UPDATE_SCHEDULED);
  event_add(ev, &(trps->update_interval));
}

static void tr_trps_sweep(int listener, short event, void *arg)
{
  struct tr_trps_event_cookie *cookie=talloc_get_type_abort(arg, struct tr_trps_event_cookie);
  TRPS_INSTANCE *trps=cookie->trps;
  struct event *ev=cookie->ev;

  tr_debug("tr_trps_sweep: sweeping routes.");
  trps_sweep_routes(trps);
  tr_trps_print_route_table(trps, stderr);
  /* schedule the event to run again */
  event_add(ev, &(trps->sweep_interval));
}

static void tr_connection_update(int listener, short event, void *arg)
{
  struct tr_trps_event_cookie *cookie=talloc_get_type_abort(arg, struct tr_trps_event_cookie);
  TRPS_INSTANCE *trps=cookie->trps;
  struct event *ev=cookie->ev;

  tr_debug("tr_connection_update: checking peer connections.");
  tr_connect_to_peers(trps, ev);
  /* schedule the event to run again */
  event_add(ev, &(trps->connect_interval));
}

static int tr_trps_events_destructor(void *obj)
{
  TR_TRPS_EVENTS *ev=talloc_get_type_abort(obj, TR_TRPS_EVENTS);
  if (ev->mq_ev!=NULL)
    event_free(ev->mq_ev);
  if (ev->connect_ev!=NULL)
    event_free(ev->connect_ev);
  if (ev->update_ev!=NULL)
    event_free(ev->update_ev);
  if (ev->sweep_ev!=NULL)
    event_free(ev->sweep_ev);
  return 0;
}
static TR_TRPS_EVENTS *tr_trps_events_new(TALLOC_CTX *mem_ctx)
{
  TR_TRPS_EVENTS *ev=talloc(mem_ctx, TR_TRPS_EVENTS);
  if (ev!=NULL) {
    ev->listen_ev=talloc(ev, struct tr_socket_event);
    ev->mq_ev=NULL;
    ev->connect_ev=NULL;
    ev->update_ev=NULL;
    ev->sweep_ev=NULL;
    if (ev->listen_ev==NULL) {
      talloc_free(ev);
      ev=NULL;
    } else {
      talloc_set_destructor((void *)ev, tr_trps_events_destructor);
    }
  }
  return ev;
}

static void tr_trps_events_free(TR_TRPS_EVENTS *ev)
{
  talloc_free(ev);
}

/* Configure the trps instance and set up its event handler.
 * Fills in trps_ev, which should be allocated by caller. */
TRP_RC tr_trps_event_init(struct event_base *base, TR_INSTANCE *tr)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_socket_event *listen_ev=NULL;
  struct tr_trps_event_cookie *trps_cookie=NULL;
  struct tr_trps_event_cookie *connection_cookie=NULL;
  struct tr_trps_event_cookie *update_cookie=NULL;
  struct tr_trps_event_cookie *sweep_cookie=NULL;
  struct timeval zero_time={0,0};
  TRP_RC retval=TRP_ERROR;

  if (tr->events != NULL) {
    tr_notice("tr_trps_event_init: tr->events was not null. Freeing before reallocating..");
    tr_trps_events_free(tr->events);
  }

  tr->events=tr_trps_events_new(tmp_ctx);
  if (tr->events == NULL) {
    tr_debug("tr_trps_event_init: unable to allocate event handles.");
    retval=TRP_NOMEM;
    goto cleanup;
  }

  /* get convenient handles */
  listen_ev=tr->events->listen_ev;

  /* Create the cookie for callbacks. It will end up part of the trps context, so it will
   * be cleaned up when trps is freed by talloc_free. */
  trps_cookie=talloc(tr->events, struct tr_trps_event_cookie);
  if (trps_cookie == NULL) {
    tr_debug("tr_trps_event_init: Unable to allocate trps_cookie.");
    retval=TRP_NOMEM;
    tr_trps_events_free(tr->events);
    tr->events=NULL;
    goto cleanup;
  }
  trps_cookie->trps=tr->trps;
  trps_cookie->cfg_mgr=tr->cfg_mgr;

  /* get a trps listener */
  listen_ev->sock_fd=trps_get_listener(tr->trps,
                                       tr_trps_msg_handler,
                                       tr_trps_gss_handler,
                                       tr->cfg_mgr->active->internal->hostname,
                                       tr->cfg_mgr->active->internal->trps_port,
                                       (void *)trps_cookie);
  if (listen_ev->sock_fd < 0) {
    tr_crit("Error opening TRP server socket.");
    retval=TRP_ERROR;
    tr_trps_events_free(tr->events);
    tr->events=NULL;
    goto cleanup;
  }
  trps_cookie->ev=listen_ev->ev; /* in case it needs to frob the event */
  
  /* and its event */
  listen_ev->ev=event_new(base,
                          listen_ev->sock_fd,
                          EV_READ|EV_PERSIST,
                          tr_trps_event_cb,
                          (void *)(tr->trps));
  event_add(listen_ev->ev, NULL);
  
  /* now set up message queue processing event, only triggered by
   * tr_trps_mq_cb() */
  tr->events->mq_ev=event_new(base,
                              0,
                              EV_PERSIST,
                              tr_trps_process_mq,
                              (void *)(tr->trps));
  tr_mq_set_notify_cb(tr->trps->mq, tr_trps_mq_cb, tr->events->mq_ev);

  /* now set up the peer connection timer event */
  connection_cookie=talloc(tr->events, struct tr_trps_event_cookie);
  if (connection_cookie == NULL) {
    tr_debug("tr_trps_event_init: Unable to allocate connection_cookie.");
    retval=TRP_NOMEM;
    tr_trps_events_free(tr->events);
    tr->events=NULL;
    goto cleanup;
  }
  connection_cookie->trps=tr->trps;
  connection_cookie->cfg_mgr=tr->cfg_mgr;
  tr->events->connect_ev=event_new(base, -1, EV_TIMEOUT, tr_connection_update, (void *)connection_cookie);
  connection_cookie->ev=tr->events->connect_ev; /* in case it needs to frob the event */
  /* The first time, do this immediately. Thereafter, it will retrigger every trps->connect_interval */
  event_add(tr->events->connect_ev, &zero_time);

  /* now set up the route update timer event */
  update_cookie=talloc(tr->events, struct tr_trps_event_cookie);
  if (update_cookie == NULL) {
    tr_debug("tr_trps_event_init: Unable to allocate update_cookie.");
    retval=TRP_NOMEM;
    tr_trps_events_free(tr->events);
    tr->events=NULL;
    goto cleanup;
  }
  update_cookie->trps=tr->trps;
  update_cookie->cfg_mgr=tr->cfg_mgr;
  tr->events->update_ev=event_new(base, -1, EV_TIMEOUT, tr_trps_update, (void *)update_cookie);
  update_cookie->ev=tr->events->update_ev; /* in case it needs to frob the event */
  event_add(tr->events->update_ev, &(tr->trps->update_interval));

  /* now set up the route table sweep timer event */
  sweep_cookie=talloc(tr->events, struct tr_trps_event_cookie);
  if (sweep_cookie == NULL) {
    tr_debug("tr_trps_event_init: Unable to allocate sweep_cookie.");
    retval=TRP_NOMEM;
    tr_trps_events_free(tr->events);
    tr->events=NULL;
    goto cleanup;
  }
  sweep_cookie->trps=tr->trps;
  sweep_cookie->cfg_mgr=tr->cfg_mgr;
  tr->events->sweep_ev=event_new(base, -1, EV_TIMEOUT, tr_trps_sweep, (void *)sweep_cookie);
  sweep_cookie->ev=tr->events->sweep_ev; /* in case it needs to frob the event */
  event_add(tr->events->sweep_ev, &(tr->trps->sweep_interval));

  talloc_steal(tr, tr->events);
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
  TR_NAME *peer_gssname=NULL;

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
    peer_gssname=trp_connection_get_peer(trpc_get_conn(trpc));
    if (peer_gssname==NULL) {
      tr_err("tr_trpc_thread: could not duplicate peer_gssname.");
      talloc_free(tmp_ctx);
      return NULL;
    }
    tr_debug("tr_trpc_thread: connected to peer %s", peer_gssname->buf);

    msg=tr_mq_msg_new(tmp_ctx, TR_MQMSG_TRPC_CONNECTED, TR_MQ_PRIO_HIGH);
    tr_mq_msg_set_payload(msg, (void *)tr_dup_name(peer_gssname), tr_free_name_helper);
    if (msg==NULL) {
      tr_err("tr_trpc_thread: error allocating TR_MQ_MSG");
      talloc_free(tmp_ctx);
      return NULL;
    }
    tr_debug("queuing********************************************************************************");
    trps_mq_add(trps, msg); /* steals msg context */
    tr_debug("queued********************************************************************************");
    msg=NULL;

    while(1) {
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

        if (0==strcmp(msg_type, TR_MQMSG_ABORT)) {
          tr_mq_msg_free(msg);
          break; /* exit loop */
        }
        else if (0==strcmp(msg_type, TR_MQMSG_TRPC_SEND)) {
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

  tr_debug("tr_trpc_thread: exiting.");
  msg=tr_mq_msg_new(tmp_ctx, TR_MQMSG_TRPC_DISCONNECTED, TR_MQ_PRIO_HIGH);
  tr_mq_msg_set_payload(msg, (void *)trpc, NULL); /* do not pass a free routine */
  if (msg==NULL)
    tr_err("tr_trpc_thread: error allocating TR_MQ_MSG");
  else
    trps_mq_add(trps, msg);

  trpc_mq_clear(trpc); /* clear any queued messages */

  talloc_free(tmp_ctx);
  return NULL;
}

/* convert an IDP realm into routing table entries. Outputs number in *n_routes */
static TRP_ROUTE **tr_make_local_routes(TALLOC_CTX *mem_ctx,
                                         TR_IDP_REALM *realm,
                                         char *trust_router,
                                         size_t *n_routes)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_APC *apc=NULL;
  TRP_ROUTE *new_entry=NULL;
  TRP_ROUTE **entries=NULL;
  size_t n_apcs=0, ii=0;

  *n_routes=0;

  if (realm==NULL)
    goto cleanup;

  /* count apcs */
  for (apc=realm->apcs, n_apcs=0; apc!=NULL; apc=apc->next,n_apcs++) {}

  entries=talloc_array(tmp_ctx, TRP_ROUTE *, n_apcs);
  for (apc=realm->apcs,ii=0; apc!=NULL; apc=apc->next, ii++) {
    new_entry=trp_route_new(entries);
    if (new_entry==NULL) {
      tr_crit("tr_make_local_routes: unable to allocate entry.");
      talloc_free(entries);
      goto cleanup;
    }
    trp_route_set_apc(new_entry, tr_dup_name(apc->id));
    trp_route_set_realm(new_entry, tr_dup_name(realm->realm_id));
    trp_route_set_peer(new_entry, tr_new_name("")); /* no peer, it's us */
    trp_route_set_metric(new_entry, 0);
    trp_route_set_trust_router(new_entry, tr_new_name(trust_router));
    trp_route_set_next_hop(new_entry, tr_new_name(""));
    trp_route_set_local(new_entry, 1);
    entries[ii]=new_entry;
  }

  talloc_steal(mem_ctx, entries);
  *n_routes=n_apcs;
 cleanup:
  talloc_free(tmp_ctx);
  return entries;
}

void tr_peer_status_change(TRP_PEER *peer, void *cookie)
{
  TRPS_INSTANCE *trps=talloc_get_type_abort(cookie, TRPS_INSTANCE);

  if (TRP_SUCCESS!=trps_wildcard_route_req(trps, trp_peer_get_servicename(peer)))
    tr_err("tr_send_wildcard: error sending wildcard route request.");
}

/* starts a trpc thread to connect to server:port */
TRP_RC tr_trpc_initiate(TRPS_INSTANCE *trps, TRP_PEER *peer, struct event *ev)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRPC_INSTANCE *trpc=NULL;
  TRP_CONNECTION *conn=NULL;
  struct trpc_thread_data *thread_data=NULL;
  TRP_RC rc=TRP_ERROR;

  tr_debug("tr_trpc_initiate entered");
  trpc=trpc_new(tmp_ctx);
  if (trpc==NULL) {
    tr_crit("tr_trpc_initiate: could not allocate TRPC_INSTANCE.");
    rc=TRP_NOMEM;
    goto cleanup;
  }
  tr_debug("tr_trpc_initiate: allocated trpc");

  conn=trp_connection_new(trpc);
  if (conn==NULL) {
    tr_crit("tr_trpc_initiate: could not allocate TRP_CONNECTION.");
    rc=TRP_NOMEM;
    goto cleanup;
  }

  trpc_set_conn(trpc, conn);
  trpc_set_server(trpc, talloc_strdup(trpc, trp_peer_get_server(peer)));
  trpc_set_port(trpc, trp_peer_get_port(peer));
  trpc_set_gssname(trpc, trp_peer_dup_gssname(peer));
  tr_debug("tr_trpc_initiate: allocated connection");
  
  /* start thread */
  thread_data=talloc(trpc, struct trpc_thread_data);
  if (thread_data==NULL) {
    tr_crit("tr_trpc_initiate: could not allocate struct trpc_thread_data.");
    rc=TRP_NOMEM;
    goto cleanup;
  }
  thread_data->trpc=trpc;
  thread_data->trps=trps;

  trps_add_trpc(trps, trpc); /* must add before starting thread */
  pthread_create(trp_connection_get_thread(conn), NULL, tr_trpc_thread, thread_data);

  tr_debug("tr_trpc_initiate: started trpc thread");
  rc=TRP_SUCCESS;

 cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

/* Add local routes to the route table. */
TRP_RC tr_add_local_routes(TRPS_INSTANCE *trps, TR_CFG *cfg)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_IDP_REALM *cur=NULL;
  TRP_ROUTE **local_routes=NULL;
  size_t n_routes=0;
  size_t ii=0;
  char *trust_router_name=talloc_asprintf(tmp_ctx, "%s:%d", cfg->internal->hostname, cfg->internal->trps_port);

  /* determine our trust router name */
  if (trust_router_name==NULL)
    return TRP_NOMEM;

  for (cur=cfg->idp_realms; cur!=NULL; cur=cur->next) {
    local_routes=tr_make_local_routes(tmp_ctx, cur, trust_router_name, &n_routes);
    for (ii=0; ii<n_routes; ii++)
      trps_add_route(trps, local_routes[ii]);

    talloc_free(local_routes);
    local_routes=NULL;
    n_routes=0;
  }

  talloc_free(tmp_ctx);
  return TRP_SUCCESS;
}

/* decide how often to attempt to connect to a peer */
static int tr_conn_attempt_due(TRPS_INSTANCE *trps, TRP_PEER *peer, struct timespec *when)
{
  return 1; /* currently make an attempt every cycle */
}

/* open missing connections to peers */
TRP_RC tr_connect_to_peers(TRPS_INSTANCE *trps, struct event *ev)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TRP_PTABLE_ITER *iter=trp_ptable_iter_new(tmp_ctx);
  TRP_PEER *peer=NULL;
  struct timespec curtime={0,0};
  TRP_RC rc=TRP_ERROR;

  if (clock_gettime(CLOCK_REALTIME, &curtime)) {
    tr_err("tr_connect_to_peers: failed to read time.");
    rc=TRP_CLOCKERR;
    goto cleanup;
  }

  for (peer=trp_ptable_iter_first(iter, trps->ptable);
       peer!=NULL;
       peer=trp_ptable_iter_next(iter))
  {
    if (trps_find_trpc(trps, peer)==NULL) {
      tr_debug("tr_connect_to_peers: %.*s missing connection.",
               trp_peer_get_gssname(peer)->len, trp_peer_get_gssname(peer)->buf);
      /* has it been long enough since we last tried? */
      if (tr_conn_attempt_due(trps, peer, &curtime)) {
        trp_peer_set_last_conn_attempt(peer, &curtime); /* we are trying again now */
        if (tr_trpc_initiate(trps, peer, ev)!=TRP_SUCCESS) {
          tr_err("tr_connect_to_peers: unable to initiate TRP connection to %s:%u.",
                 trp_peer_get_server(peer),
                 trp_peer_get_port(peer));
        } 
      }
    }
  }
  rc=TRP_SUCCESS;
    
cleanup:
  trp_ptable_iter_free(iter);
  talloc_free(tmp_ctx);
  return rc;
}


/* Called by the config manager after a change to the active configuration.
 * Updates configuration of objects that do not know about the config manager. */
void tr_config_changed(TR_CFG *new_cfg, void *cookie)
{
  TR_INSTANCE *tr=talloc_get_type_abort(cookie, TR_INSTANCE);
  TRPS_INSTANCE *trps=tr->trps;

  tr->cfgwatch->poll_interval.tv_sec=new_cfg->internal->cfg_poll_interval;
  tr->cfgwatch->poll_interval.tv_usec=0;

  tr->cfgwatch->settling_time.tv_sec=new_cfg->internal->cfg_settling_time;
  tr->cfgwatch->settling_time.tv_usec=0;

  trps_set_connect_interval(trps, new_cfg->internal->trp_connect_interval);
  trps_set_update_interval(trps, new_cfg->internal->trp_update_interval);
  trps_set_sweep_interval(trps, new_cfg->internal->trp_sweep_interval);
  trps_clear_rtable(trps); /* should we do this every time??? */
  tr_add_local_routes(trps, new_cfg); /* should we do this every time??? */
  trps_update_active_routes(trps); /* find new routes */
  trps_update(trps, TRP_UPDATE_TRIGGERED); /* send any triggered routes */
  tr_trps_print_route_table(trps, stderr);
}

