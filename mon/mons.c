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
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <tr.h>
#include <tr_debug.h>
#include <mon_internal.h>
#include <tr_socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <tr_gss.h>

#include "mons_handlers.h"

static void mons_sweep_procs(MONS_INSTANCE *mons);

static int mons_destructor(void *object)
{
  MONS_INSTANCE *mons = talloc_get_type_abort(object, MONS_INSTANCE);
  if (mons->handlers)
    g_ptr_array_unref(mons->handlers);

  if (mons->pids)
    g_array_unref(mons->pids);

  return 0;
}

/**
 * Allocate a new MONS_INSTANCE
 *
 * @param mem_ctx talloc context for allocation
 * @return new MONS_INSTANCE or null on failure
 */
MONS_INSTANCE *mons_new(TALLOC_CTX *mem_ctx)
{
  MONS_INSTANCE *mons = talloc(mem_ctx, MONS_INSTANCE);

  if (mons) {
    mons->hostname = NULL;
    mons->mon_port = 0;
    mons->tids = NULL;
    mons->trps = NULL;
    mons->req_handler = NULL;
    mons->auth_handler = NULL;
    mons->cookie = NULL;

    /* Before any steps that may fail, install the destructor */
    talloc_set_destructor((void *)mons, mons_destructor);

    mons->authorized_gss_names = tr_gss_names_new(mons);
    if (mons->authorized_gss_names == NULL) {
      talloc_free(mons);
      return NULL;
    }

    mons->handlers = g_ptr_array_new();
    if (mons->handlers == NULL) {
      talloc_free(mons);
      return NULL;
    }

    mons->pids = g_array_new(FALSE, FALSE, sizeof(pid_t));
    if (mons->pids == NULL) {
      talloc_free(mons);
      return NULL;
    }
  }
  return mons;
}

/**
 * Callback to process a request and produce a response
 *
 * @param req_str JSON-encoded request
 * @param data pointer to a MONS_INSTANCE
 * @return pointer to the response string or null to send no response
 */
static TR_GSS_RC mons_req_cb(TALLOC_CTX *mem_ctx, TR_MSG *req_msg, TR_MSG **resp_msg, void *data)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  MONS_INSTANCE *mons = talloc_get_type_abort(data, MONS_INSTANCE);
  MON_REQ *req = NULL;
  MON_RESP *resp = NULL;
  TR_GSS_RC rc = TR_GSS_ERROR;

  /* Validate inputs */
  if (req_msg == NULL)
    goto cleanup;

  req = tr_msg_get_mon_req(req_msg);
  if (req == NULL) {
    /* this is an internal error */
    tr_err("mons_req_cb: Received incorrect message type (was %d, expected %d)",
           tr_msg_get_msg_type(req_msg),
           MON_REQUEST);
    /* TODO send an error response */
    goto cleanup;
  }

  /* Allocate a response message */
  *resp_msg = talloc(tmp_ctx, TR_MSG);
  if (*resp_msg == NULL) {
    /* can't return a message, just emit an error */
    tr_crit("mons_req_cb: Error allocating response message.");
    goto cleanup;
  }

  /* Handle the request */
  resp = mons_handle_request(*resp_msg, mons, req);
  if (resp == NULL) {
    /* error processing the request */
    /* TODO send back an error */
    *resp_msg = NULL; /* null this out so the caller doesn't mistake it for valid */
    goto cleanup;
  }

  /* Set the response message payload */
  tr_msg_set_mon_resp(*resp_msg, resp);

  /* Put the response message in the caller's context so it does not get freed when we exit */
  talloc_steal(mem_ctx, *resp_msg);
  rc = TR_GSS_SUCCESS;

cleanup:
  talloc_free(tmp_ctx);
  return rc;
}

/**
 * Create a listener for monitoring requests
 *
 * Accept connections with mons_accept()
 *
 * @param mons monitoring server instance
 * @param req_handler
 * @param auth_handler
 * @param hostname
 * @param port
 * @param cookie
 * @param fd_out
 * @param max_fd
 * @return
 */
int mons_get_listener(MONS_INSTANCE *mons,
                      MONS_REQ_FUNC *req_handler,
                      MONS_AUTH_FUNC *auth_handler,
                      const char *hostname,
                      int port,
                      void *cookie,
                      int *fd_out,
                      size_t max_fd)
{
  size_t n_fd=0;
  size_t ii=0;

  mons->mon_port = port;
  n_fd = tr_sock_listen_all(port, fd_out, max_fd);
  if (n_fd<=0)
    tr_err("mons_get_listener: Error opening port %d", port);
  else {
    /* opening port succeeded */
    tr_info("mons_get_listener: Opened port %d.", port);

    /* make this socket non-blocking */
    for (ii=0; ii<n_fd; ii++) {
      if (0 != fcntl(fd_out[ii], F_SETFL, O_NONBLOCK)) {
        tr_err("mons_get_listener: Error setting O_NONBLOCK.");
        for (ii=0; ii<n_fd; ii++) {
          close(fd_out[ii]);
          fd_out[ii]=-1;
        }
        n_fd=0;
        break;
      }
    }
  }

  if (n_fd>0) {
    /* store the caller's request handler & cookie */
    mons->req_handler = req_handler;
    mons->auth_handler = auth_handler;
    mons->hostname = hostname;
    mons->cookie = cookie;
  }

  return (int) n_fd;
}

/**
 * Process to handle an incoming monitoring request
 *
 * This should be run in a child process after fork(). Handles the request
 * and terminates. Never returns to the caller.
 *
 * @param mons the monitoring server instance
 * @param conn_fd file descriptor for the incoming connection
 */
static void mons_handle_proc(MONS_INSTANCE *mons, int conn_fd)
{
  struct rlimit rlim; /* for disabling core dump */

  switch(tr_gss_handle_connection(conn_fd,
                                  "trustmonitor", mons->hostname, /* acceptor name */
                                  mons->auth_handler, mons->cookie, /* auth callback and cookie */
                                  mons_req_cb, mons /* req callback and cookie */
  )) {
    case TR_GSS_SUCCESS:
      /* do nothing */
      break;

    case TR_GSS_ERROR:
      tr_debug("mons_accept: Error returned by tr_gss_handle_connection()");
      break;

    default:
      tr_err("mons_accept: Unexpected value returned by tr_gss_handle_connection()");
      break;
  }
  close(conn_fd);

  /* This ought to be an exit(0), but log4shib does not play well with fork() due to
   * threading issues. To ensure we do not get stuck in the exit handler, we will
   * abort. First disable core dump for this subprocess (the main process will still
   * dump core if the environment allows). */
  rlim.rlim_cur = 0; /* max core size of 0 */
  rlim.rlim_max = 0; /* prevent the core size limit from being raised later */
  setrlimit(RLIMIT_CORE, &rlim);
  abort(); /* exit hard */
}

/**
 * Accept and process a connection on a port opened with mons_get_listener()
 *
 * @param mons monitoring interface instance
 * @param listen FD of the connection socket
 * @return 0 on success
 */
int mons_accept(MONS_INSTANCE *mons, int listen)
{
  int conn=-1;
  int pid=-1;

  if (0 > (conn = tr_sock_accept(listen))) {
    tr_debug("mons_accept: Error accepting connection");
    return 1;
  }

  if (0 > (pid = fork())) {
    perror("Error on fork()");
    return 1;
  }

  if (pid == 0) {
    /* Only the child process gets here */
    close(listen); /* this belongs to the parent */
    mons_handle_proc(mons, conn); /* never returns */
  }

  /* Only the parent process gets here */
  close(conn); /* this belongs to the child */
  g_array_append_val(mons->pids, pid);

  /* clean up any processes that have completed */
  mons_sweep_procs(mons);

  return 0;
}

void mons_sweep_procs(MONS_INSTANCE *mons)
{
  guint ii;
  pid_t pid;
  int status;

  /* loop backwards over the array so we can remove elements as we go */
  for (ii=mons->pids->len; ii > 0; ii--) {
    /* ii-1 is the current index */
    pid = g_array_index(mons->pids, pid_t, ii-1);
    if (waitpid(pid, &status, WNOHANG) > 0) {
      /* the process exited */
      tr_debug("mons_sweep_procs: monitoring process %d terminated.", pid);

      g_array_remove_index_fast(mons->pids, ii-1); /* disturbs only indices >= ii-1 which we've already handled */
      if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0)
          tr_debug("mons_sweep_procs: monitoring process %d succeeded.", pid);
        else
          tr_debug("mons_sweep_procs: monitoring process %d exited with status %d.", pid, WTERMSIG(status));
      } else if (WIFSIGNALED(status)) {
        tr_debug("mons_sweep_procs: monitoring process %d terminated by signal %d.", pid, WTERMSIG(status));
      }
    }
  }
}
