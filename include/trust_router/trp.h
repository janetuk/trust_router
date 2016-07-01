#ifndef TRP_H
#define TRP_H

#include <talloc.h>

#define TRP_PORT 12310
#define TRP_METRIC_INFINITY 0xFFFF
#define TRP_METRIC_INVALID 0xFFFFFFFF
#define TRP_INTERVAL_INVALID 0

typedef enum trp_rc {
  TRP_SUCCESS=0,
  TRP_ERROR, /* generic error */
  TRP_NOPARSE, /* parse error */
  TRP_NOMEM, /* allocation error */
  TRP_BADTYPE, /* typing error */
  TRP_UNSUPPORTED, /* unsupported feature */
  TRP_BADARG, /* bad argument */
} TRP_RC;

typedef enum trp_inforec_type {
  TRP_INFOREC_TYPE_UNKNOWN=0, /* conveniently, JSON parser returns 0 if a non-integer number is specified */
  TRP_INFOREC_TYPE_ROUTE,
  TRP_INFOREC_TYPE_COMMUNITY, /* not yet implemented (2016-06-14) */
} TRP_INFOREC_TYPE;

typedef struct trp_inforec TRP_INFOREC;

typedef struct trp_update TRP_UPD;
typedef struct trp_req TRP_REQ;

/* Functions for TRP_UPD structures */
TR_EXPORT TRP_UPD *trp_upd_new(TALLOC_CTX *mem_ctx);
void trp_upd_free(TRP_UPD *update);
TR_EXPORT TRP_INFOREC *trp_upd_get_inforec(TRP_UPD *upd);
void trp_upd_set_inforec(TRP_UPD *upd, TRP_INFOREC *rec);
TR_EXPORT TR_NAME *trp_upd_get_peer(TRP_UPD *upd);
TRP_RC trp_upd_set_peer(TRP_UPD *upd, TR_NAME *peer);
TR_EXPORT TRP_INFOREC *trp_inforec_new(TALLOC_CTX *mem_ctx, TRP_INFOREC_TYPE type);
void trp_inforec_free(TRP_INFOREC *rec);
TR_EXPORT TRP_INFOREC *trp_inforec_get_next(TRP_INFOREC *rec);
void trp_inforec_set_next(TRP_INFOREC *rec, TRP_INFOREC *next_rec);
TR_EXPORT TRP_INFOREC_TYPE trp_inforec_get_type(TRP_INFOREC *rec);
void trp_inforec_set_type(TRP_INFOREC *rec, TRP_INFOREC_TYPE type);
TR_EXPORT TR_NAME *trp_inforec_get_comm(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_comm(TRP_INFOREC *rec, TR_NAME *comm);
TR_EXPORT TR_NAME *trp_inforec_get_realm(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_realm(TRP_INFOREC *rec, TR_NAME *realm);
TR_EXPORT TR_NAME *trp_inforec_get_trust_router(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_trust_router(TRP_INFOREC *rec, TR_NAME *trust_router);
TR_EXPORT TR_NAME *trp_inforec_get_next_hop(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_next_hop(TRP_INFOREC *rec, TR_NAME *next_hop);
TR_EXPORT unsigned int trp_inforec_get_metric(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_metric(TRP_INFOREC *rec, unsigned int metric);
TR_EXPORT unsigned int trp_inforec_get_interval(TRP_INFOREC *rec);
TRP_RC trp_inforec_set_interval(TRP_INFOREC *rec, unsigned int interval);
TR_EXPORT TRP_INFOREC_TYPE trp_inforec_type_from_string(const char *s);
TR_EXPORT const char *trp_inforec_type_to_string(TRP_INFOREC_TYPE msgtype);

/* Functions for TRP_REQ structures */
TR_EXPORT TRP_REQ *trp_req_new(TALLOC_CTX *mem_ctx);
TR_EXPORT void trp_req_free(TRP_REQ *req);
TR_EXPORT TR_NAME *trp_req_get_comm(TRP_REQ *req);
void trp_req_set_comm(TRP_REQ *req, TR_NAME *comm);
TR_EXPORT TR_NAME *trp_req_get_realm(TRP_REQ *req);
void trp_req_set_realm(TRP_REQ *req, TR_NAME *realm);
TR_EXPORT TR_NAME *trp_req_get_peer(TRP_REQ *req);
TRP_RC trp_req_set_peer(TRP_REQ *req, TR_NAME *peer);

#endif /* TRP_H */
