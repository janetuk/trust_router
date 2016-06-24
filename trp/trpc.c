#include <fcntl.h>
#include <event2/event.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>

#include <gsscon.h>
#include <tr_rp.h>
#include <tr_config.h>
#include <tr_event.h>
#include <tr_debug.h>
#include <tr_trp.h>


TRPC_INSTANCE *trpc_new (TALLOC_CTX *mem_ctx)
{
  return talloc_zero(mem_ctx, TRPC_INSTANCE);
}

void trpc_free (TRPC_INSTANCE *trpc)
{
  if (trpc)
    talloc_free(trpc);
}

/* Connect to a TRP server */
int trpc_open_connection (TRPC_INSTANCE *trpc, 
                          char *server,
                          unsigned int port,
                          gss_ctx_id_t *gssctx)
{
  int err = 0;
  int conn = -1;
  unsigned int use_port = 0;

  if (0 == port)
    use_port = TRP_PORT;
  else 
    use_port = port;

  tr_debug("trpc_open_connection: opening GSS connection to %s:%d", server, use_port);
  err = gsscon_connect(server, use_port, "trustrouter", &conn, gssctx);

  if (!err)
    return conn;
  else
    return -1;
}


/* simple function, based on tidc_send_req */
int trpc_send_msg (TRPC_INSTANCE *trpc, 
                   int conn, 
                   gss_ctx_id_t gssctx,
                   const char *msg_content,
                   int *resp_handler(),
                   void *cookie)
{
  char *resp_buf=NULL;
  size_t resp_buflen=0;
  int err=0;
  int rc=0;

  /* Send the request over the connection */
  if (err = gsscon_write_encrypted_token (conn,
                                          gssctx,
                                          msg_content, 
                                          strlen(msg_content))) {
    tr_err( "trpc_send_msg: Error sending message over connection.\n");
    goto error;
  }

  /* Read the response from the connection */
  if (err = gsscon_read_encrypted_token(conn, gssctx, &resp_buf, &resp_buflen)) {
    if (resp_buf)
      free(resp_buf);
    goto error;
  }

  tr_debug( "trpc_send_msg: Response Received (%u bytes).\n", (unsigned) resp_buflen);
  tr_debug( "%s\n", resp_buf);

  if (resp_handler)
    /* Call the caller's response function */
    (*resp_handler)(trpc, resp_buf, cookie);
  goto cleanup;

 error:
  rc = -1;
 cleanup:
  if (resp_buf)
    free(resp_buf);
  return rc;
}
