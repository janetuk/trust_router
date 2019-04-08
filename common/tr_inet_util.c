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

#include <tr_name_internal.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>

#include <tr_inet_util.h>
#include <errno.h>

/**
 * Determine whether a string is a valid address of a given family
 *
 * @param s string to check
 * @param af address family (probably AF_INET or AF_INET6)
 * @return 1 if string is a valid address in the given family, 0 if not, -1 on error (errno set)
 */
static int is_valid_address(int af, const char *s)
{
  unsigned char buf[sizeof(struct in6_addr)];

  if (s == NULL)
    return 0;
  return inet_pton(af, s, buf);
}

/**
 * Determine whether a string is a valid IPv6 address reference
 *
 * I.e., an IPv6 address in brackets
 *
 * @param s string to validate
 * @return 1 if a valid reference, 0 otherwise
 */
static int tr_valid_ipv6_reference(const char *s)
{
  char *cpy;
  size_t len;
  int valid_ipv6;

  /* check that it starts with an open bracket */
  if (*s != '[')
    return 0;

  /* check that it ends with a close bracket */
  len = strlen(s);
  if (*(s+len-1) != ']')
    return 0;

  /* make a null-terminated copy of the string omitting the brackets */
  cpy = talloc_strndup(NULL, s+1, len-2);
  if (cpy == NULL)
    return 0; /* an error occurred - fail safe */

  valid_ipv6 = is_valid_address(AF_INET6, cpy);
  talloc_free(cpy);

  return valid_ipv6;
}

/**
 * Validate a host string
 *
 * The intention is to reject strings that may appear to contain a ':port' spec.
 * Takes a permissive view of valid: a hostname is valid if either it is a
 * bracketed IPv6 address reference ([address]) or has no brackets or colons.
 * This accepts all valid DNS names and IPv4 addresses, as well as many invalid
 * hostnames. This is ok for accepting a hostname that will later be resolved
 * because invalid names will fail to resolve. It should *not* be used to ensure
 * a hostname is compliant with RFC!
 *
 * Ignores a trailing colon followed by decimal digits.
 *
 * @param s string to validate
 * @return 1 if a valid host specification, 0 otherwise
 */
static int tr_valid_host(const char *s)
{
  if (strchr(s, '[') || strchr(s, ']'))
    return tr_valid_ipv6_reference(s);

  return 1;
}

/**
 * Check that all characters are decimal digits
 *
 * @param s
 * @return 1 if all digits, 0 otherwise
 */
static int tr_str_all_digits(const char *s)
{
  if (s == NULL)
    return 0;

  for( ; *s; s++) {
    if ( (*s < '0') || (*s > '9'))
      return 0;
  }

  return 1;
}

/**
 * Validate and parse a hostname or hostname/port
 *
 * If port_out is not null, accepts a port as well. This is
 * stored in *port_out. If no port is given, a 0 is stored.
 * If an invalid port is given, -1 is stored.
 *
 * If the hostname is invalid, null is returned and no value
 * is written to *port_out.
 *
 * If port_out is null, null will be returned if the string
 * contains a port.
 *
 * The return value must be freed with talloc_free unless
 * it is null.
 *
 * @param mem_ctx talloc context for hostname result
 * @param s string to parse
 * @param port_out pointer to an allocated integer, or NULL
 * @return pointer to the hostname or null on error
 */
char *tr_parse_host(TALLOC_CTX *mem_ctx, const char *s, int *port_out)
{
  const char *colon;
  char *hostname;
  int port;

  if (s == NULL)
    return NULL;

  /* If we are accepting a port, find the last colon. */
  if (port_out == NULL)
    colon = NULL;
  else
    colon = strrchr(s, ':');

  /* If there are more than one colon, and the last one is not preceeded by ],
     this is not a port separator, but an IPv6 address (likely) */
  if (strchr(s, ':') != colon && *(colon - 1) != ']')
    colon = NULL;

  /* Get a copy of the hostname portion, which may be the entire string. */
  if (colon == NULL)
    hostname = talloc_strdup(NULL, s);
  else
    hostname = talloc_strndup(NULL, s, colon-s);

  if (hostname == NULL)
    return NULL; /* failed to dup the hostname */

  /* Check that the hostname is valid; if not, return null and ignore the port. */
  if (! tr_valid_host(hostname)) {
    talloc_free(hostname);
    return NULL;
  }

  /* If we are accepting a port, parse and validate it. */
  if (port_out != NULL) {
    if (colon == NULL) {
      *port_out = 0;
    } else {
      port = tr_parse_port(colon+1);
      if ((port > 0) && tr_str_all_digits(colon+1))
        *port_out = port;
      else
        *port_out = -1;
    }
  }

  return hostname;
}

TR_NAME *tr_hostname_and_port_to_name(TR_NAME *hn, int port)
{
  TR_NAME *retval = NULL;
  char *s = NULL;
  char *hn_s = tr_name_strdup(hn);

  if (!hn_s)
    return NULL;

  s = talloc_asprintf(NULL, "%s:%d", hn_s, port);
  free(hn_s);

  if (s) {
    retval = tr_new_name(s);
    talloc_free(s);
  }

  return retval;
}

/**
 * Parse a string containing a port
 *
 * Returns the port number, which is always in the range 1-65535.
 * On error, returns < 0. The absolute value is an error code from errno.h
 *
 * @param s
 * @return port number or < 0 on error
 */
int tr_parse_port(const char *s)
{
  long port;
  char *end;

  errno = 0; /* strtol sets this, make sure it's zero to avoid false positives */
  port = strtol(s, &end, 10);
  if (errno) {
    return -errno;
  }

  if (*end != '\0') {
    return -EINVAL;
  }

  if ((port <= 0) || (port > 65535)) {
    return -ERANGE;
  }

  return (int) port;
}
