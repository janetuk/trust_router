#ifndef TRP_INTERNAL_H
#define TRP_INTERNAL_H

#include <talloc.h>

#include <gsscon.h>
#include <trust_router/tr_dh.h>

#define TRP_PORT 12310

typedef struct trp_req {
  int msg;
} TRP_REQ;

typedef struct trp_resp {
  int msg;
} TRP_RESP;

typedef struct trps_instance TRPS_INSTANCE;

typedef int (TRPS_REQ_FUNC)(TRPS_INSTANCE *, TRP_REQ *, TRP_RESP *, void *);
typedef void (TRPS_RESP_FUNC)(TRPS_INSTANCE *, TRP_REQ *, TRP_RESP *, void *);
typedef int (trps_auth_func)(gss_name_t client_name, TR_NAME *display_name, void *cookie);


/* encapsulate a gss context and its connection file handle */
typedef struct trps_connection {
  int conn;
  gss_ctx_id_t *gssctx;
} TRPS_CONNECTION;

/* a collection of the above */
#define TRPS_CONNECTIONS_MAX 10;
typedef struct trps_connection_set {
  TRPS_CONNECTION *conn[TRPS_CONNECTIONS_MAX];
  unsigned int nconn;
} TRPS_CONNECTION_SET;

/* TRP Client Instance Data */
typedef struct trpc_instance {
  DH *client_dh;			/* Client's DH struct with priv and pub keys */
} TRPC_INSTANCE;

/* TRP Server Instance Data */
struct trps_instance {
  char *hostname;
  unsigned int port;
  TRPS_REQ_FUNC *req_handler;
  trps_auth_func *auth_handler;
  void *cookie;
  struct tr_rp_client *rp_gss;		/* Client matching GSS name, TBD -- FIX ME (??) */
  TRPS_CONNECTION_SET *connections; /* active GSS connections */
};

typedef enum {
  TRPS_ERR_OK=0, /* success */
  TRPS_ERR_NOMEM, /* allocation problem */
  TRPS_ERR_MAX_CONN, /* out of connections */
  TRPS_ERR_UNKNOWN /* catch-all */
} TRPS_ERR;

/* prototypes */

/* these should probably  be static? */
TRPS_CONNECTION *trps_connection_new(TALLOC_CTX *mem_ctx);
TRPS_CONNECTION_SET *trps_connection_set_new(TALLOC_CTX *mem_ctx);
TRPS_ERR trps_connection_set_add(TRPS_CONNECTION_SET *tcs, TRPS_CONNECTION *new_conn);
TRPS_ERR trps_connection_set_del(TRPS_CONNECTION_SET *tcs, TRPS_CONNECTION *conn);
unsigned int trps_connection_set_len(TRPS_CONNECTION_SET *tcs);

TRPC_INSTANCE *trpc_create (TALLOC_CTX *mem_ctx);
void trpc_destroy (TRPC_INSTANCE *trpc);
int trpc_open_connection (TRPC_INSTANCE *trpc, char *server, unsigned int port, gss_ctx_id_t *gssctx);
int trpc_send_msg (TRPC_INSTANCE *trpc, int conn, gss_ctx_id_t gssctx, const char *msg_content,
                   int *resp_handler(), void *cookie);

TRPS_INSTANCE *trps_create (TALLOC_CTX *mem_ctx);
void trps_destroy (TRPS_INSTANCE *trps);
int trps_send_msg (TRPS_INSTANCE *trps, int conn, gss_ctx_id_t gssctx, const char *msg_content);
int trps_accept(TRPS_INSTANCE *trps, int listen);

#endif /* TRP_INTERNAL_H */
