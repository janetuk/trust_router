#include <jansson.h>
#include <talloc.h>

#include <trust_router/tr_name.h>
#include <trp_internal.h>
#include <tr_debug.h>

static int trp_req_destructor(void *object)
{
  TRP_REQ *req=talloc_get_type_abort(object, TRP_REQ);
  
  /* clean up TR_NAME data, which are not managed by talloc */
  if (req->comm != NULL)
    tr_free_name(req->comm);

  if (req->realm != NULL)
    tr_free_name(req->realm);

  if (req->peer != NULL)
    tr_free_name(req->peer);

  return 0;
}

TRP_REQ *trp_req_new(TALLOC_CTX *mem_ctx)
{
  TRP_REQ *new_req=talloc(mem_ctx, TRP_REQ);

  if (new_req != NULL) {
    new_req->comm=NULL;
    new_req->realm=NULL;
    new_req->peer=NULL;
  }

  talloc_set_destructor((void *)new_req, trp_req_destructor);
  return new_req;
}

void trp_req_free(TRP_REQ *req)
{
  if (req!=NULL)
    talloc_free(req);
}

TR_NAME *trp_req_get_comm(TRP_REQ *req)
{
  if (req!=NULL)
    return req->comm;
  else
    return NULL;
}

void trp_req_set_comm(TRP_REQ *req, TR_NAME *comm)
{
  if (req)
    req->comm=comm;
}

TR_NAME *trp_req_get_realm(TRP_REQ *req)
{
  if (req!=NULL)
    return req->realm;
  else
    return NULL;
}


void trp_req_set_realm(TRP_REQ *req, TR_NAME *realm)
{
  if (req)
    req->realm=realm;
}

TR_NAME *trp_req_get_peer(TRP_REQ *req)
{
  if (req!=NULL)
    return req->peer;
  else
    return NULL;
}


void trp_req_set_peer(TRP_REQ *req, TR_NAME *peer)
{
  if (req)
    req->peer=peer;
}
