/*
 * Copyright (c) 2018, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <talloc.h>
#include <gssapi.h>
#include <string.h>

#include <tr_msg.h>
#include <tr_debug.h>
#include <gsscon.h>
#include <tr_gss.h>

/**
 * tr_gss.c - GSS connection handler
 *
 * The chief entry point to this module is tr_gss_handle_connection(). This
 * function accepts an incoming socket connection, runs the GSS authorization
 * and authentication process, accepts a request, processes it, then sends
 * the reply and returns without closing the connection.
 *
 * Callers need to provide two callbacks, each with a cookie for passing
 * custom data to the callback.
 *
 *   * TR_GSS_AUTH_FN auth_cb: Authorization callback
 *     - This callback is used during the GSS auth process to determine whether
 *       a credential should be authorized to connect.
 *
 *   * TR_GSS_HANDLE_REQ_FN req_cb: Request handler callback
 *     - After auth, this callback is passed the string form of the incoming request.
 *       It should process the request and return a string form of the outgoing
 *       response, if any.
 */

typedef struct tr_gss_cookie {
  TR_GSS_AUTH_FN *auth_cb;
  void *auth_cookie;
} TR_GSS_COOKIE;

static int tr_gss_auth_cb(gss_name_t clientName, gss_buffer_t displayName, void *data)
{
  TR_GSS_COOKIE *cookie = talloc_get_type_abort(data, TR_GSS_COOKIE);
  TR_NAME name ={(char *) displayName->value, (int) displayName->length};
  int result=0;

  if (cookie->auth_cb(clientName, &name, cookie->auth_cookie)) {
    tr_debug("tr_gss_auth_cb: client '%.*s' denied authorization.", name.len, name.buf);
    result=EACCES; /* denied */
  }

  return result;
}


/**
 * Handle GSS authentication and authorization
 *
 * @param conn connection file descriptor
 * @param acceptor_name name of acceptor to present to initiator
 * @param acceptor_realm realm of acceptor to present to initiator
 * @param gssctx GSS context
 * @param auth_cb authorization callback
 * @param auth_cookie generic data to pass to the authorization callback
 * @return 0 on successful auth, 1 on disallowed auth, -1 on error
 */
static int tr_gss_auth_connection(int conn,
                                  const char *acceptor_name,
                                  const char *acceptor_realm,
                                  gss_ctx_id_t *gssctx,
                                  TR_GSS_AUTH_FN auth_cb,
                                  void *auth_cookie)
{
  int rc = 0;
  int auth, autherr = 0;
  gss_buffer_desc nameBuffer = {0, NULL};
  TR_GSS_COOKIE *cookie = NULL;

  nameBuffer.value = talloc_asprintf(NULL, "%s@%s", acceptor_name, acceptor_realm);
  if (nameBuffer.value == NULL) {
    tr_err("tr_gss_auth_connection: Error allocating acceptor name.");
    return -1;
  }
  nameBuffer.length = strlen(nameBuffer.value);

  /* Set up for the auth callback. There are two layers of callbacks here: we
   * use our own, which handles gsscon interfacing and calls the auth_cb parameter
   * to do the actual auth. Store the auth_cb information in a metacookie. */
  cookie = talloc(NULL, TR_GSS_COOKIE);
  cookie->auth_cb=auth_cb;
  cookie->auth_cookie=auth_cookie;

  /* Now call gsscon with *our* auth callback and cookie */
  rc = gsscon_passive_authenticate(conn, nameBuffer, gssctx, tr_gss_auth_cb, cookie);
  talloc_free(cookie);
  talloc_free(nameBuffer.value);
  if (rc) {
    tr_debug("tr_gss_auth_connection: Error from gsscon_passive_authenticate(), rc = %d.", rc);
    return -1;
  }

  rc = gsscon_authorize(*gssctx, &auth, &autherr);
  if (rc) {
    tr_debug("tr_gss_auth_connection: Error from gsscon_authorize, rc = %d, autherr = %d.",
             rc, autherr);
    return -1;
  }

  if (auth)
    tr_debug("tr_gss_auth_connection: Connection authenticated, conn = %d.", conn);
  else
    tr_debug("tr_gss_auth_connection: Authentication failed, conn %d.", conn);

  return !auth;
}

/**
 * Read a request from the GSS connection
 *
 * @param mem_ctx talloc context for the result
 * @param conn file descriptor for the connection
 * @param gssctx GSS context
 * @return talloc'ed string containing the request, or null on error
 */
static char *tr_gss_read_req(TALLOC_CTX *mem_ctx, int conn, gss_ctx_id_t gssctx)
{
  int err;
  char *retval = NULL;
  char *buf = NULL;
  size_t buflen = 0;

  err = gsscon_read_encrypted_token(conn, gssctx, &buf, &buflen);
  if (err || (buf == NULL)) {
    if (buf)
      free(buf);
    tr_debug("tr_gss_read_req: Error reading from connection, rc=%d", err);
    return NULL;
  }

  tr_debug("tr_gss_read_req: Read %u bytes.", (unsigned) buflen);

  // get a talloc'ed version, guaranteed to have a null termination
  retval = talloc_asprintf(mem_ctx, "%.*s", (int) buflen, buf);
  free(buf);

  return retval;
}

/**
 * Write a response to the GSS connection
 *
 * @param conn file descriptor for the connection
 * @param gssctx GSS context
 * @param resp encoded response string to send
 * @return 0 on success, -1 on error
 */
static int tr_gss_write_resp(int conn, gss_ctx_id_t gssctx, const char *resp)
{
  int err = 0;

  /* Send the response over the connection */
  err = gsscon_write_encrypted_token (conn, gssctx, resp, strlen(resp) + 1);
  if (err) {
    tr_debug("tr_gss_send_response: Error sending response over connection, rc=%d.", err);
    return -1;
  }
  return 0;
}

/**
 * Handle a request/response connection
 *
 * Authorizes/authenticates the connection, then reads a response, passes that to a
 * callback to get a response, sends that, then returns.
 *
 * @param conn connection file descriptor
 * @param acceptor_name acceptor name to present
 * @param acceptor_realm acceptor realm to present
 * @param auth_cb callback for authorization
 * @param auth_cookie cookie for the auth_cb
 * @param req_cb callback to handle the request and produce the response
 * @param req_cookie cookie for the req_cb
 */
void tr_gss_handle_connection(int conn,
                              const char *acceptor_name,
                              const char *acceptor_realm,
                              TR_GSS_AUTH_FN auth_cb,
                              void *auth_cookie,
                              TR_GSS_HANDLE_REQ_FN req_cb,
                              void *req_cookie)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  gss_ctx_id_t gssctx = GSS_C_NO_CONTEXT;
  char *req_str = NULL;
  char *resp_str = NULL;

  if (tr_gss_auth_connection(conn,
                             acceptor_name,
                             acceptor_realm,
                             &gssctx,
                             auth_cb,
                             auth_cookie)) {
    tr_notice("tr_gss_handle_connection: Error authorizing connection.");
    goto cleanup;
  }

  tr_debug("tr_gss_handle_connection: Connection authorized");

  // TODO: should there be a timeout on this?
  while (1) {	/* continue until an error breaks us out */
    // try to read a request
    req_str = tr_gss_read_req(tmp_ctx, conn, gssctx);

    if ( req_str == NULL) {
      // an error occurred, give up
      tr_notice("tr_gss_handle_connection: Error reading request");
      goto cleanup;
    } else if (strlen(req_str) > 0) {
      // we got a request message, exit the loop and process it
      break;
    }

    // no error, but no message, keep waiting for one
    talloc_free(req_str); // this would be cleaned up anyway, but may as well free it
  }

  /* Hand off the request for processing and get the response */
  resp_str = req_cb(tmp_ctx, req_str, req_cookie);

  if (resp_str == NULL) {
    // no response, clean up
    goto cleanup;
  }

  // send the response
  if (tr_gss_write_resp(conn, gssctx, resp_str)) {
    tr_notice("tr_gss_handle_connection: Error writing response");
  }

cleanup:
  talloc_free(tmp_ctx);
}
