#ifndef TRP_INTERNAL_H
#define TRP_INTERNAL_H

#include <pthread.h>
#include <talloc.h>

#include <gsscon.h>
#include <trust_router/tr_dh.h>
#include <tr_mq.h>
#include <tr_msg.h>
#include <trust_router/trp.h>

/* info records */
/* TRP update record types */
typedef struct trp_inforec_route {
  TR_NAME *comm;
  TR_NAME *realm;
  TR_NAME *trust_router;
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
};

struct trp_req {
  TR_NAME *comm;
  TR_NAME *realm;
};


typedef struct trps_instance TRPS_INSTANCE;

typedef enum trp_connection_status {
  TRP_CONNECTION_DOWN=0,
  TRP_CONNECTION_UP,
} TRP_CONNECTION_STATUS;

typedef struct trp_connection TRP_CONNECTION;
struct trp_connection {
  pthread_mutex_t mutex; /* protects status attribute */
  TRP_CONNECTION *next;
  pthread_t *thread; /* thread servicing this connection */
  int fd;
  TR_NAME *gssname;
  gss_ctx_id_t *gssctx;
  TRP_CONNECTION_STATUS status;
};

typedef TRP_RC (*TRPS_MSG_FUNC)(TRPS_INSTANCE *, TRP_CONNECTION *, TR_MSG *);
typedef void (*TRP_RESP_FUNC)();
/*typedef int (*TRP_AUTH_FUNC)(gss_name_t client_name, TR_NAME *display_name, void *cookie);*/
typedef client_cb_fn TRP_AUTH_FUNC;

/* TRP Client Instance Data */
typedef struct trpc_instance TRPC_INSTANCE;
struct trpc_instance {
  TRPC_INSTANCE *next;
  const char *server;
  unsigned int port;
  TRP_CONNECTION *conn;
  TR_MQ *mq; /* msgs from master to trpc */
  DH *dh;			/* Client's DH struct with priv and pub keys */
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
  TR_MQ *mq;
};


TRP_CONNECTION *trp_connection_new(TALLOC_CTX *mem_ctx);
void trp_connection_free(TRP_CONNECTION *conn);
void trp_connection_close(TRP_CONNECTION *conn);
int trp_connection_lock(TRP_CONNECTION *conn);
int trp_connection_unlock(TRP_CONNECTION *conn);
int trp_connection_get_fd(TRP_CONNECTION *conn);
void trp_connection_set_fd(TRP_CONNECTION *conn, int fd);
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
TRP_RC trp_connection_initiate(TRP_CONNECTION *conn, const char *server, unsigned int port);

TRPC_INSTANCE *trpc_new (TALLOC_CTX *mem_ctx);
void trpc_free (TRPC_INSTANCE *trpc);
TRP_CONNECTION *trpc_get_conn(TRPC_INSTANCE *trpc);
void trpc_set_conn(TRPC_INSTANCE *trpc, TRP_CONNECTION *conn);
TRPC_INSTANCE *trpc_get_next(TRPC_INSTANCE *trpc);
void trpc_set_next(TRPC_INSTANCE *trpc, TRPC_INSTANCE *next);
TRPC_INSTANCE *trpc_remove(TRPC_INSTANCE *trpc, TRPC_INSTANCE *remove);
void trpc_append(TRPC_INSTANCE *trpc, TRPC_INSTANCE *new);
const char *trpc_get_server(TRPC_INSTANCE *trpc);
void trpc_set_server(TRPC_INSTANCE *trpc, const char *server);
unsigned int trpc_get_port(TRPC_INSTANCE *trpc);
void trpc_set_port(TRPC_INSTANCE *trpc, unsigned int port);
DH *trpc_get_dh(TRPC_INSTANCE *trpc);
void trpc_set_dh(TRPC_INSTANCE *trpc, DH *dh);
TRP_CONNECTION_STATUS trpc_get_status(TRPC_INSTANCE *trpc);
TR_MQ *trpc_get_mq(TRPC_INSTANCE *trpc);
void trpc_set_mq(TRPC_INSTANCE *trpc, TR_MQ *mq);
void trpc_mq_append(TRPC_INSTANCE *trpc, TR_MQ_MSG *msg);
TR_MQ_MSG *trpc_mq_pop(TRPC_INSTANCE *trpc);
void trpc_master_mq_append(TRPC_INSTANCE *trpc, TR_MQ_MSG *msg);
TR_MQ_MSG *trpc_master_mq_pop(TRPC_INSTANCE *trpc);
TRP_RC trpc_connect(TRPC_INSTANCE *trpc);
TRP_RC trpc_send_msg(TRPC_INSTANCE *trpc, const char *msg_content);

TRPS_INSTANCE *trps_new (TALLOC_CTX *mem_ctx);
void trps_free (TRPS_INSTANCE *trps);
TRP_RC trps_send_msg (TRPS_INSTANCE *trps, void *peer, const char *msg);
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
int trps_auth_cb(gss_name_t clientName, gss_buffer_t displayName, void *data);
TR_MQ_MSG *trps_mq_pop(TRPS_INSTANCE *trps);
void trps_mq_append(TRPS_INSTANCE *trps, TR_MQ_MSG *msg);
void trps_handle_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *conn);
#endif /* TRP_INTERNAL_H */
