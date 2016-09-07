#ifndef TRP_INTERNAL_H
#define TRP_INTERNAL_H

#include <pthread.h>
#include <talloc.h>

#include <gsscon.h>
#include <tr_mq.h>
#include <tr_msg.h>
#include <trp_ptable.h>
#include <trp_rtable.h>
#include <trust_router/trp.h>

/* info records */
/* TRP update record types */
typedef struct trp_inforec_route {
  TR_NAME *comm;
  TR_NAME *realm;
  TR_NAME *trust_router;
  TR_NAME *next_hop;
  unsigned int next_hop_port;
  unsigned int metric;
  unsigned int interval;
} TRP_INFOREC_ROUTE;

/* TODO: define struct trp_msg_info_community */

typedef union trp_inforec_data {
  TRP_INFOREC_ROUTE *route;
  /* TRP_INFOREC_COMM *comm; */
} TRP_INFOREC_DATA;

struct trp_inforec {
  TRP_INFOREC *next;
  TRP_INFOREC_TYPE type;
  TRP_INFOREC_DATA data; /* contains pointer to one of the record types */
};

struct trp_update {
  TRP_INFOREC *records;
  TR_NAME *peer; /* who did this update come from? */
};

struct trp_req {
  TR_NAME *comm;
  TR_NAME *realm;
  TR_NAME *peer; /* who did this req come from? */
};


typedef struct trps_instance TRPS_INSTANCE;

typedef enum trp_connection_status {
  TRP_CONNECTION_CLOSED=0,
  TRP_CONNECTION_DOWN,  
  TRP_CONNECTION_AUTHORIZING,  
  TRP_CONNECTION_UP,
  TRP_CONNECTION_UNKNOWN,
} TRP_CONNECTION_STATUS;

typedef struct trp_connection TRP_CONNECTION;
struct trp_connection {
  pthread_mutex_t mutex; /* protects status attribute */
  TRP_CONNECTION *next;
  pthread_t *thread; /* thread servicing this connection */
  int fd;
  TR_NAME *gssname;
  TR_NAME *peer; /* TODO: why is there a peer and a gssname? jlr */
  gss_ctx_id_t *gssctx;
  TRP_CONNECTION_STATUS status;
  void (*status_change_cb)(TRP_CONNECTION *conn, void *cookie);
  void *status_change_cookie;
};

typedef TRP_RC (*TRPS_MSG_FUNC)(TRPS_INSTANCE *, TRP_CONNECTION *, TR_MSG *);
typedef void (*TRP_RESP_FUNC)();
/*typedef int (*TRP_AUTH_FUNC)(gss_name_t client_name, TR_NAME *display_name, void *cookie);*/
typedef client_cb_fn TRP_AUTH_FUNC;

/* function to look up comm/realm entries */
typedef TRP_ROUTE *(TRP_LOOKUP_FUNC)(TR_NAME *, TR_NAME *, void *);


/* TRP Client Instance Data */
typedef struct trpc_instance TRPC_INSTANCE;
struct trpc_instance {
  TRPC_INSTANCE *next;
  TR_NAME *gssname;
  char *server;
  unsigned int port;
  TRP_CONNECTION *conn;
  TR_MQ *mq; /* msgs from master to trpc */
};

/* TRP Server Instance Data */
struct trps_instance {
  char *hostname;
  unsigned int port;
  TRP_AUTH_FUNC auth_handler;
  TRPS_MSG_FUNC msg_handler;
  void *cookie;
  TRP_CONNECTION *conn; /* connections from peers */
  TRPC_INSTANCE *trpc; /* connections to peers */
  TR_MQ *mq; /* incoming message queue */
  TRP_PTABLE *ptable; /* peer table */
  TRP_RTABLE *rtable; /* route table */
  struct timeval connect_interval; /* interval between connection refreshes */
  struct timeval update_interval; /* interval between scheduled updates */
  struct timeval sweep_interval; /* interval between route table sweeps */
};

typedef enum trp_update_type {
  TRP_UPDATE_SCHEDULED=0,
  TRP_UPDATE_TRIGGERED,
  TRP_UPDATE_REQUESTED
} TRP_UPDATE_TYPE;

TRP_CONNECTION *trp_connection_new(TALLOC_CTX *mem_ctx);
void trp_connection_free(TRP_CONNECTION *conn);
void trp_connection_close(TRP_CONNECTION *conn);
int trp_connection_lock(TRP_CONNECTION *conn);
int trp_connection_unlock(TRP_CONNECTION *conn);
int trp_connection_get_fd(TRP_CONNECTION *conn);
void trp_connection_set_fd(TRP_CONNECTION *conn, int fd);
TR_NAME *trp_connection_get_peer(TRP_CONNECTION *conn);
TR_NAME *trp_connection_get_gssname(TRP_CONNECTION *conn);
void trp_connection_set_gssname(TRP_CONNECTION *conn, TR_NAME *gssname);
gss_ctx_id_t *trp_connection_get_gssctx(TRP_CONNECTION *conn);
void trp_connection_set_gssctx(TRP_CONNECTION *conn, gss_ctx_id_t *gssctx);
TRP_CONNECTION_STATUS trp_connection_get_status(TRP_CONNECTION *conn);
pthread_t *trp_connection_get_thread(TRP_CONNECTION *conn);
void trp_connection_set_thread(TRP_CONNECTION *conn, pthread_t *thread);
TRP_CONNECTION *trp_connection_get_next(TRP_CONNECTION *conn);
TRP_CONNECTION *trp_connection_remove(TRP_CONNECTION *conn, TRP_CONNECTION *remove);
void trp_connection_append(TRP_CONNECTION *conn, TRP_CONNECTION *new);
int trp_connection_auth(TRP_CONNECTION *conn, TRP_AUTH_FUNC auth_callback, void *callback_data);
TRP_CONNECTION *trp_connection_accept(TALLOC_CTX *mem_ctx, int listen, TR_NAME *gssname);
TRP_RC trp_connection_initiate(TRP_CONNECTION *conn, char *server, unsigned int port);

TRPC_INSTANCE *trpc_new (TALLOC_CTX *mem_ctx);
void trpc_free (TRPC_INSTANCE *trpc);
TRP_CONNECTION *trpc_get_conn(TRPC_INSTANCE *trpc);
void trpc_set_conn(TRPC_INSTANCE *trpc, TRP_CONNECTION *conn);
TRPC_INSTANCE *trpc_get_next(TRPC_INSTANCE *trpc);
void trpc_set_next(TRPC_INSTANCE *trpc, TRPC_INSTANCE *next);
TRPC_INSTANCE *trpc_remove(TRPC_INSTANCE *trpc, TRPC_INSTANCE *remove);
void trpc_append(TRPC_INSTANCE *trpc, TRPC_INSTANCE *new);
char *trpc_get_server(TRPC_INSTANCE *trpc);
void trpc_set_server(TRPC_INSTANCE *trpc, char *server);
TR_NAME *trpc_get_gssname(TRPC_INSTANCE *trpc);
void trpc_set_gssname(TRPC_INSTANCE *trpc, TR_NAME *gssname);
unsigned int trpc_get_port(TRPC_INSTANCE *trpc);
void trpc_set_port(TRPC_INSTANCE *trpc, unsigned int port);
TRP_CONNECTION_STATUS trpc_get_status(TRPC_INSTANCE *trpc);
TR_MQ *trpc_get_mq(TRPC_INSTANCE *trpc);
void trpc_set_mq(TRPC_INSTANCE *trpc, TR_MQ *mq);
void trpc_mq_add(TRPC_INSTANCE *trpc, TR_MQ_MSG *msg);
TR_MQ_MSG *trpc_mq_pop(TRPC_INSTANCE *trpc);
void trpc_mq_clear(TRPC_INSTANCE *trpc);
void trpc_master_mq_add(TRPC_INSTANCE *trpc, TR_MQ_MSG *msg);
TR_MQ_MSG *trpc_master_mq_pop(TRPC_INSTANCE *trpc);
TRP_RC trpc_connect(TRPC_INSTANCE *trpc);
TRP_RC trpc_send_msg(TRPC_INSTANCE *trpc, const char *msg_content);

TRPS_INSTANCE *trps_new (TALLOC_CTX *mem_ctx);
void trps_free (TRPS_INSTANCE *trps);
void trps_set_ptable(TRPS_INSTANCE *trps, TRP_PTABLE *ptable);
void trps_set_peer_status_callback(TRPS_INSTANCE *trps, void (*cb)(TRP_PEER *, void *), void *cookie);
TRP_RC trps_init_rtable(TRPS_INSTANCE *trps);
void trps_clear_rtable(TRPS_INSTANCE *trps);
void trps_set_connect_interval(TRPS_INSTANCE *trps, unsigned int interval);
unsigned int trps_get_connect_interval(TRPS_INSTANCE *trps);
void trps_set_update_interval(TRPS_INSTANCE *trps, unsigned int interval);
unsigned int trps_get_update_interval(TRPS_INSTANCE *trps);
void trps_set_sweep_interval(TRPS_INSTANCE *trps, unsigned int interval);
unsigned int trps_get_sweep_interval(TRPS_INSTANCE *trps);
TRPC_INSTANCE *trps_find_trpc(TRPS_INSTANCE *trps, TRP_PEER *peer);
TRP_RC trps_send_msg (TRPS_INSTANCE *trps, TRP_PEER *peer, const char *msg);
void trps_add_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *new);
void trps_remove_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *remove);
void trps_add_trpc(TRPS_INSTANCE *trps, TRPC_INSTANCE *trpc);
void trps_remove_trpc(TRPS_INSTANCE *trps, TRPC_INSTANCE *remove);
int trps_get_listener(TRPS_INSTANCE *trps,
                      TRPS_MSG_FUNC msg_handler,
                      TRP_AUTH_FUNC auth_handler,
                      const char *hostname,
                      unsigned int port,
                      void *cookie);
TR_MQ_MSG *trps_mq_pop(TRPS_INSTANCE *trps);
void trps_mq_add(TRPS_INSTANCE *trps, TR_MQ_MSG *msg);
TRP_RC trps_authorize_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *conn);
void trps_handle_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *conn);
TRP_RC trps_update_active_routes(TRPS_INSTANCE *trps);
TRP_RC trps_handle_tr_msg(TRPS_INSTANCE *trps, TR_MSG *tr_msg);
TRP_ROUTE *trps_get_route(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm, TR_NAME *peer);
TRP_ROUTE *trps_get_selected_route(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm);
TR_NAME *trps_get_next_hop(TRPS_INSTANCE *trps, TR_NAME *comm, TR_NAME *realm);
TRP_RC trps_sweep_routes(TRPS_INSTANCE *trps);
TRP_RC trps_add_route(TRPS_INSTANCE *trps, TRP_ROUTE *route);
TRP_RC trps_add_peer(TRPS_INSTANCE *trps, TRP_PEER *peer);
TRP_PEER *trps_get_peer_by_gssname(TRPS_INSTANCE *trps, TR_NAME *gssname);
TRP_PEER *trps_get_peer_by_servicename(TRPS_INSTANCE *trps, TR_NAME *servicename);
TRP_RC trps_update(TRPS_INSTANCE *trps, TRP_UPDATE_TYPE type);
int trps_peer_connected(TRPS_INSTANCE *trps, TRP_PEER *peer);
TRP_RC trps_wildcard_route_req(TRPS_INSTANCE *trps, TR_NAME *peer_gssname);
#endif /* TRP_INTERNAL_H */
