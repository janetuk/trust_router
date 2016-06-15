#ifndef TRP_INTERNAL_H
#define TRP_INTERNAL_H

#include <talloc.h>

#include <gsscon.h>
#include <trust_router/tr_dh.h>

#define TRP_PORT 12310
#define TRP_METRIC_INFINITY 0xFFFF

typedef enum trp_rc {
  TRP_SUCCESS=0,
  TRP_ERROR, /* generic error */
  TRP_NOPARSE, /* parse error */
  TRP_NOMEM, /* allocation error */
  TRP_BADTYPE, /* typing error */
  TRP_UNSUPPORTED, /* unsupported feature */
} TRP_RC;

/*** Messages ***/
typedef enum trp_msg_type {
  TRP_MSG_TYPE_UNKNOWN=0, /* conveniently, JSON parser returns 0 if a non-integer number is specified */
  TRP_MSG_TYPE_UPDATE,
  TRP_MSG_TYPE_ROUTE_REQ
} TRP_MSG_TYPE;

/* info records */
typedef enum trp_msg_info_type {
  TRP_MSG_INFO_TYPE_UNKNOWN=0, /* conveniently, JSON parser returns 0 if a non-integer number is specified */
  TRP_MSG_INFO_TYPE_ROUTE,
  TRP_MSG_INFO_TYPE_COMMUNITY, /* not yet implemented (2016-06-14) */
} TRP_MSG_INFO_TYPE;

typedef struct trp_msg {
  TRP_MSG_TYPE type;
  void *body;
} TRP_MSG;

/* update msg record types */
typedef struct trp_msg_info_route TRP_MSG_INFO_ROUTE;
struct trp_msg_info_route {
  void *next;
  TRP_MSG_INFO_TYPE type;
  TR_NAME *comm;
  TR_NAME *realm;
  TR_NAME *trust_router;
  unsigned int metric;
  unsigned int interval;
};

/* TODO: define struct trp_msg_info_community */

typedef struct trp_route_update {
  void *records;
} TRP_ROUTE_UPDATE;

typedef struct trp_route_req {
  TR_NAME *comm;
  TR_NAME *realm;
} TRP_ROUTE_REQ;

TRP_MSG_TYPE trp_msg_type_from_string(const char *s);
const char *trp_msg_type_to_string(TRP_MSG_TYPE msgtype);
TRP_MSG_INFO_TYPE trp_msg_info_type_from_string(const char *s);
const char *trp_msg_info_type_to_string(TRP_MSG_INFO_TYPE msgtype);

TRP_MSG *trp_msg_new(TALLOC_CTX *mem_ctx);
void trp_msg_destroy(TRP_MSG *msg);
void trp_msg_pprint(TRP_MSG *msg);
char *trp_encode_msg(TRP_MSG *msg);


typedef struct trps_instance TRPS_INSTANCE;

/* REMOVE THIS!! --jennifer, 2016-06-13 */
typedef TRP_MSG TRP_REQ;
typedef TRP_MSG TRP_RESP;


typedef int (TRPS_REQ_FUNC)(TRPS_INSTANCE *, TRP_REQ *, TRP_RESP *, void *);
typedef void (TRPS_RESP_FUNC)(TRPS_INSTANCE *, TRP_REQ *, TRP_RESP *, void *);
typedef int (trps_auth_func)(gss_name_t client_name, TR_NAME *display_name, void *cookie);


/* encapsulate a gss context and its connection file handle */
typedef struct trps_connection {
  int conn;
  gss_ctx_id_t *gssctx;
} TRPS_CONNECTION;

/* a collection of the above */
#define TRPS_CONNECTIONS_MAX 10
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
