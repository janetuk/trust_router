/*
 * Copyright (c) 2016-2018, JANET(UK)
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
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h> // for nfds_t
#include <sys/socket.h>

#include <tr_debug.h>
#include <tr_socket.h>
#include <errno.h>

/**
 * Open sockets on all interface addresses
 *
 * Uses getaddrinfo() to find all TCP addresses and opens sockets in
 * non-blocking modes. Binds to most max_fd sockets and stores file descriptors
 * in fd_out. Unused entries in fd_out are not modified. Returns the actual
 * number of sockets opened.
 *
 * @param port port to listen on
 * @param fd_out output array, at least max_fd long
 * @param max_fd maximum number of file descriptors to write
 * @return number of file descriptors written into the output array
 */
nfds_t tr_sock_listen_all(int port, int *fd_out, nfds_t max_fd)
{
  int rc = 0;
  int conn = -1;
  int optval = 1;
  int gai_retval = 0;
  struct addrinfo *ai=NULL;
  struct addrinfo *ai_head=NULL;
  struct addrinfo hints={
      .ai_flags=AI_PASSIVE,
      .ai_family=AF_UNSPEC,
      .ai_socktype=SOCK_STREAM,
      .ai_protocol=IPPROTO_TCP
  };
  char *port_str=NULL;
  nfds_t n_opened=0;

  port_str=talloc_asprintf(NULL, "%d", port);
  if (port_str==NULL) {
    tr_err("tr_sock_listen_all: unable to allocate port");
    return 0;
  }

  gai_retval = getaddrinfo(NULL, port_str, &hints, &ai_head);
  talloc_free(port_str);
  if (gai_retval != 0) {
    tr_err("tr_sock_listen_all: getaddrinfo() failed (%s)", gai_strerror(gai_retval));
    return 0;
  }
  tr_debug("tr_sock_listen_all: got address info");

  /* TODO: listen on all ports - I don't recall what this means (jlr, 4/11/2018) */
  for (ai=ai_head,n_opened=0; (ai!=NULL)&&(n_opened<max_fd); ai=ai->ai_next) {
    if (0 > (conn = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))) {
      tr_debug("tr_sock_listen_all: unable to open socket");
      continue;
    }

    optval=1;
    if (0!=setsockopt(conn, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)))
      tr_debug("tids_listen: unable to set SO_REUSEADDR"); /* not fatal? */

    if (ai->ai_family==AF_INET6) {
      /* don't allow IPv4-mapped IPv6 addresses (per RFC4942, not sure
       * if still relevant) */
      if (0!=setsockopt(conn, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval))) {
        tr_debug("tr_sock_listen_all: unable to set IPV6_V6ONLY, skipping interface");
        close(conn);
        continue;
      }
    }

    rc=bind(conn, ai->ai_addr, ai->ai_addrlen);
    if (rc<0) {
      tr_debug("tr_sock_listen_all: unable to bind to socket");
      close(conn);
      continue;
    }

    if (0>listen(conn, 512)) {
      tr_debug("tr_sock_listen_all: unable to listen on bound socket");
      close(conn);
      continue;
    }

    /* ok, this one worked. Save it */
    fd_out[n_opened++]=conn;
  }
  freeaddrinfo(ai_head);

  if (n_opened==0) {
    tr_debug("tr_sock_listen_all: no addresses available for listening.");
    return 0;
  }

  tr_debug("tr_sock_listen_all: listening on port %d on %d socket%s",
           port,
           n_opened,
           (n_opened==1)?"":"s");

  return n_opened;
}

/**
 * Extract a string-formatted socket address from a struct sockaddr
 *
 * @param s
 * @param dst pointer to allocated space of at least INET6_ADDRSLEN bytes
 * @param dst_len size of space allocated at dst
 * @return pointer to dst or null on error
 */
static const char *tr_sock_ip_address(struct sockaddr *s, char *dst, size_t dst_len)
{
  switch (s->sa_family) {
    case AF_INET:
      inet_ntop(AF_INET,
                &(((struct sockaddr_in *)s)->sin_addr),
                dst,
                (socklen_t) dst_len);
      break;

    case AF_INET6:
      inet_ntop(AF_INET6,
                &(((struct sockaddr_in6 *)s)->sin6_addr),
                dst,
                (socklen_t) dst_len);
      break;

    default:
      snprintf(dst, dst_len, "addr family %u", s->sa_family);
      break;
  }

  return dst;
}

/**
 * Accept a socket connection
 *
 * @param sock
 * @return -1 on error, connection fd on success
 */
int tr_sock_accept(int sock)
{
  int conn = -1;
  union {
    /* This gives us a block of memory the size of sockaddr_storage that is also labeled by
     * a sockaddr. This avoids strict-aliasing problems with gcc. */
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } peeraddr;
  socklen_t addr_len = sizeof(peeraddr);
  char peeraddr_string[INET6_ADDRSTRLEN];
#define TR_S_A_MAX_ERR_LEN 80
  char err[TR_S_A_MAX_ERR_LEN];

  if (0 > (conn = accept(sock, &(peeraddr.addr), &addr_len))) {
    if (strerror_r(errno, err, sizeof(err)))
      snprintf(err, sizeof(err), "errno = %d", errno);
    tr_debug("tr_sock_accept: Unable to accept connection: %s", err);
  } else {
    tr_info("tr_sock_accept: Incoming connection on fd %d from %s",
              conn,
              tr_sock_ip_address(&(peeraddr.addr),
                                 peeraddr_string,
                                 sizeof(peeraddr_string)));
  }
  return conn;
}
