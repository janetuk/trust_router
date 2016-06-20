#ifndef TRP_INTERNAL_H
#define TRP_INTERNAL_H

#include <talloc.h>

#include <gsscon.h>
#include <trust_router/tr_dh.h>
#include <trust_router/trp.h>

/* info records */
typedef enum trp_inforec_type {
  TRP_INFOREC_TYPE_UNKNOWN=0, /* conveniently, JSON parser returns 0 if a non-integer number is specified */
  TRP_INFOREC_TYPE_ROUTE,
  TRP_INFOREC_TYPE_COMMUNITY, /* not yet implemented (2016-06-14) */
} TRP_INFOREC_TYPE;

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

typedef struct trp_inforec TRP_INFOREC;
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

TRP_UPD *trp_upd_new(TALLOC_CTX *mem_ctx);
void trp_upd_free(TRP_UPD *update);
TRP_INFOREC *trp_upd_get_inforec(TRP_UPD *upd);
void trp_upd_set_inforec(TRP_UPD *upd, TRP_INFOREC *rec);
TRP_INFOREC *trp_inforec_new(TALLOC_CTX *mem_ctx, TRP_INFOREC_TYPE type);
void trp_inforec_free(TRP_INFOREC *rec);
TRP_INFOREC *trp_inforec_get_next(TRP_INFOREC *rec);
void trp_inforec_set_next(TRP_INFOREC *rec, TRP_INFOREC *next_rec);
TRP_INFOREC_TYPE trp_inforec_get_type(TRP_INFOREC *rec);
void trp_inforec_set_type(TRP_INFOREC *rec, TRP_INFOREC_TYPE type);
TR_NAME *trp_inforec_get_comm(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_comm(TRP_INFOREC *rec, TR_NAME *comm);
TR_NAME *trp_inforec_get_realm(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_realm(TRP_INFOREC *rec, TR_NAME *realm);
TR_NAME *trp_inforec_get_trust_router(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_trust_router(TRP_INFOREC *rec, TR_NAME *trust_router);
unsigned int trp_inforec_get_metric(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_metric(TRP_INFOREC *rec, unsigned int metric);
unsigned int trp_inforec_get_interval(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_interval(TRP_INFOREC *rec, unsigned int interval);
TRP_INFOREC_TYPE trp_inforec_type_from_string(const char *s);
const char *trp_inforec_type_to_string(TRP_INFOREC_TYPE msgtype);


TRP_REQ *trp_req_new(TALLOC_CTX *mem_ctx);
void trp_req_free(TRP_REQ *req);
TR_NAME *trp_req_get_comm(TRP_REQ *req);
void trp_req_set_comm(TRP_REQ *req, TR_NAME *comm);
TR_NAME *trp_req_get_realm(TRP_REQ *req);
void trp_req_set_realm(TRP_REQ *req, TR_NAME *realm);

typedef struct trps_instance TRPS_INSTANCE;

typedef int (TRPS_REQ_FUNC)();
typedef void (TRPS_RESP_FUNC)();
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
