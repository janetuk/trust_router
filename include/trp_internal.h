#ifndef TRP_INTERNAL_H
#define TRP_INTERNAL_H

#include <pthread.h>
#include <talloc.h>

#include <gsscon.h>
#include <trust_router/tr_dh.h>
#include <tr_mq.h>
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

typedef int (*TRP_REQ_FUNC)();
typedef void (*TRP_RESP_FUNC)();
/*typedef int (*TRP_AUTH_FUNC)(gss_name_t client_name, TR_NAME *display_name, void *cookie);*/
typedef client_cb_fn TRP_AUTH_FUNC;

typedef enum trp_connection_status {
  TRP_CONNECTION_DOWN=0,
  TRP_CONNECTION_UP,
} TRP_CONNECTION_STATUS;

typedef struct trp_connection TRP_CONNECTION;
struct trp_connection {
  TRP_CONNECTION *next;
  pthread_t *thread; /* thread servicing this connection */
  int fd;
  TR_NAME *gssname;
  gss_ctx_id_t *gssctx;
  TRP_CONNECTION_STATUS status;
  pthread_mutex_t status_mutex;
};

/* TRP Client Instance Data */
typedef struct trpc_instance {
  TRP_CONNECTION *conn;
  DH *client_dh;			/* Client's DH struct with priv and pub keys */
} TRPC_INSTANCE;

/* TRP Server Instance Data */
struct trps_instance {
  char *hostname;
  unsigned int port;
  TRP_AUTH_FUNC auth_handler;
  TRP_REQ_FUNC req_handler;
  void *cookie;
  TRP_CONNECTION *conn; /* connections to peers */
  TR_MQ *mq;
};


TRP_CONNECTION *trp_connection_new(TALLOC_CTX *mem_ctx);
void trp_connection_free(TRP_CONNECTION *conn);
int trp_connection_get_fd(TRP_CONNECTION *conn);
void trp_connection_set_fd(TRP_CONNECTION *conn, int fd);
TR_NAME *trp_connection_get_gssname(TRP_CONNECTION *conn);
void trp_connection_set_gssname(TRP_CONNECTION *conn, TR_NAME *gssname);
gss_ctx_id_t *trp_connection_get_gssctx(TRP_CONNECTION *conn);
void trp_connection_set_gssctx(TRP_CONNECTION *conn, gss_ctx_id_t *gssctx);
TRP_CONNECTION_STATUS trp_connection_get_status(TRP_CONNECTION *conn);
void trp_connection_set_status(TRP_CONNECTION *conn, TRP_CONNECTION_STATUS status);
pthread_t *trp_connection_get_thread(TRP_CONNECTION *conn);
void trp_connection_set_thread(TRP_CONNECTION *conn, pthread_t *thread);
TRP_CONNECTION *trp_connection_get_next(TRP_CONNECTION *conn);
void trp_connection_append(TRP_CONNECTION *conn, TRP_CONNECTION *new);
int trp_connection_auth(TRP_CONNECTION *conn, TRP_AUTH_FUNC auth_callback, void *callback_data);
TRP_CONNECTION *trp_connection_accept(TALLOC_CTX *mem_ctx, int listen, TR_NAME *gssname,
                                      TRP_AUTH_FUNC auth_callback, TRP_REQ_FUNC req_handler,
                                      void *callback_data);

TRPC_INSTANCE *trpc_new (TALLOC_CTX *mem_ctx);
void trpc_free (TRPC_INSTANCE *trpc);
int trpc_open_connection (TRPC_INSTANCE *trpc, char *server, unsigned int port, gss_ctx_id_t *gssctx);
int trpc_send_msg (TRPC_INSTANCE *trpc, int conn, gss_ctx_id_t gssctx, const char *msg_content,
                   int *resp_handler(), void *cookie);

TRPS_INSTANCE *trps_new (TALLOC_CTX *mem_ctx);
void trps_free (TRPS_INSTANCE *trps);
int trps_send_msg (TRPS_INSTANCE *trps, int conn, gss_ctx_id_t gssctx, const char *msg_content);
int trps_accept(TRPS_INSTANCE *trps, int listen);
void trps_add_connection(TRPS_INSTANCE *trps, TRP_CONNECTION *new);
int trps_get_listener(TRPS_INSTANCE *trps,
                      TRP_REQ_FUNC req_handler,
                      TRP_AUTH_FUNC auth_handler,
                      const char *hostname,
                      unsigned int port,
                      void *cookie);
int trps_auth_cb(gss_name_t clientName, gss_buffer_t displayName, void *data);
TR_MQ_MSG *trps_mq_pop(TRPS_INSTANCE *trps);
void trps_mq_append(TRPS_INSTANCE *trps, TR_MQ_MSG *msg);
#endif /* TRP_INTERNAL_H */
