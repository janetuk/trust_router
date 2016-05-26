#ifndef TR_TRP_H
#define TR_TRP_H

#include <talloc.h>

#include <tr_config.h>
#include <tr_event.h>


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


/* TRP Server Instance Data */
struct trps_instance {
  char *hostname;
  unsigned int port;
  TRPS_REQ_FUNC *req_handler;
  trps_auth_func *auth_handler;
  void *cookie;
  struct tr_rp_client *rp_gss;		/* Client matching GSS name, TBD -- FIX ME (??) */
};


/* prototypes */
TRPS_INSTANCE *trps_create (TALLOC_CTX *mem_ctx);
void trps_destroy (TRPS_INSTANCE *trps);
int tr_trps_event_init(struct event_base *base, TRPS_INSTANCE *trps, TR_CFG_MGR *cfg_mgr,
                       struct tr_socket_event *trps_ev);
int trps_accept(TRPS_INSTANCE *trps, int listen);

#endif /* TR_TRP_H */
