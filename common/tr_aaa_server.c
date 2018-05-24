/*
 * Copyright (c) 2012-2018, JANET(UK)
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

#include <tr_name_internal.h>
#include <tr_aaa_server.h>
#include <trust_router/tid.h>

static int tr_aaa_server_destructor(void *obj)
{
  TR_AAA_SERVER *aaa=talloc_get_type_abort(obj, TR_AAA_SERVER);
  if (aaa->hostname!=NULL)
    tr_free_name(aaa->hostname);
  return 0;
}

TR_AAA_SERVER *tr_aaa_server_new(TALLOC_CTX *mem_ctx)
{
  TR_AAA_SERVER *aaa=talloc(mem_ctx, TR_AAA_SERVER);
  if (aaa!=NULL) {
    aaa->next=NULL;
    aaa->hostname = NULL;
    tr_aaa_server_set_port(aaa, 0); /* go through setter to guarantee consistent default */
    talloc_set_destructor((void *)aaa, tr_aaa_server_destructor);
  }
  return aaa;
}

void tr_aaa_server_free(TR_AAA_SERVER *aaa)
{
  talloc_free(aaa);
}

TR_NAME *tr_aaa_server_get_hostname(TR_AAA_SERVER *aaa)
{
  return aaa->hostname;
}

/**
 * Set the hostname for a AAA server
 *
 * Takes ownership of the TR_NAME. Does nothing if aaa is null.
 *
 * @param aaa
 * @param hostname
 */
void tr_aaa_server_set_hostname(TR_AAA_SERVER *aaa, TR_NAME *hostname)
{
  if (aaa == NULL)
    return;

  if (aaa->hostname != NULL) {
    tr_free_name(aaa->hostname);
  }

  aaa->hostname = hostname;
}

int tr_aaa_server_get_port(TR_AAA_SERVER *aaa)
{
  return aaa->port;
}

/**
 * Set the port for a AAA server
 *
 * If port is 0, uses the standard TID port (12309). Other invalid values are stored
 * as-is.
 *
 * Does nothing if aaa is null.
 *
 * @param aaa
 * @param port
 */
void tr_aaa_server_set_port(TR_AAA_SERVER *aaa, int port)
{
  if (aaa == NULL)
    return;

  if (port == 0)
    port = TID_PORT;

  aaa->port = port;
}

/**
 * Parse the port from a hostname:port string
 *
 * @param s string to parse
 * @return the specified port, 0 if none specified, -1 if invalid
 */
static int tr_aaa_server_parse_port(const char *s)
{
  const char *s_port;
  char *end_of_conversion;
  long int port; /* long instead of int because we use strtol */

  /* Find the first colon */
  s_port = strchr(s, ':'); /* port starts at s_port + 1 */
  if (s_port == NULL)
    return 0; /* no port */

  /* Check that the last colon is the same as the first */
  if (strrchr(s, ':') != s_port)
    return -1; /* multiple colons are invalid*/

  s_port += 1; /* port now starts at s_port */

  /* Parse the port number */
  port = strtol(s, &end_of_conversion, /* base */ 10);

  /* validate */
  if ((end_of_conversion == s_port) /* there was no port, just a colon */
      || (*end_of_conversion != '\0') /* did not reach the end of the string */
      || (port <= 0) || (port > 65535)) {
    return -1;
  }

  return (int) port;
}

/**
 * Parse a hostname out of a hostname:port string
 *
 * The ":port" section is optional. Ignores the string after the first colon.
 * Does not validate the port section of the name.
 *
 * An empty hostname is allowed (but s must not be null)
 *
 * @param s
 * @return TR_NAME or null on error (i.e., out-of-memory)
 */
static TR_NAME *tr_aaa_server_parse_hostname(const char *s)
{
  const char *colon;
  char *hostname;
  size_t hostname_len;
  TR_NAME *retval;

  if (s == NULL)
    return NULL;

  /* find the colon */
  colon = strchr(s, ':');
  if (colon == NULL)
    return tr_new_name(s); /* there was no colon, take the whole string */

  /* make a copy of the hostname portion of the string */
  hostname_len = colon - s;
  hostname = malloc(hostname_len + 1); /* +1 for the null termination */
  if (hostname == NULL)
    return NULL;

  /* copy up to the colon, add a null termination, and make a TR_NAME */
  strncpy(hostname, s, hostname_len);
  hostname[hostname_len] = '\0';
  retval = tr_new_name(hostname);

  /* clean up and return */
  free(hostname);
  return retval;
}

/**
 * Allocate a AAA server record and fill it in by parsing a hostname:port string
 *
 * Does not validate hostname or port values. The port will be -1 if the port
 * could not be parsed properly.
 *
 * @return newly allocated TR_AAA_SERVER in the mem_ctx context, or NULL on error
 */
TR_AAA_SERVER *tr_aaa_server_from_string(TALLOC_CTX *mem_ctx, const char *s)
{
  TALLOC_CTX *tmp_ctx = talloc_new(NULL);
  TR_AAA_SERVER *aaa = tr_aaa_server_new(tmp_ctx);

  if (aaa == NULL)
    goto failed;

  tr_aaa_server_set_hostname(aaa, tr_aaa_server_parse_hostname(s));
  if (tr_aaa_server_get_hostname(aaa) == NULL)
    goto failed;

  tr_aaa_server_set_port(aaa, tr_aaa_server_parse_port(s));
  talloc_steal(mem_ctx, aaa); /*put this in the caller's context */
  goto succeeded;

failed:
  aaa = NULL; /* talloc will free the memory if it was allocated */

succeeded:
  talloc_free(tmp_ctx);
  return aaa;
}


/**
 * Allocate a AAA server record and fill it in by parsing a hostname:port TR_NAME
 *
 * Does not validate hostname or port values. The port will be -1 if the port
 * could not be parsed properly.
 *
 * @return newly allocated TR_AAA_SERVER in the mem_ctx context, or NULL on error
 */
TR_AAA_SERVER *tr_aaa_server_from_name(TALLOC_CTX *mem_ctx, TR_NAME *n)
{
  TR_AAA_SERVER *aaa = NULL;
  char *s = tr_name_strdup(n);
  if (s != NULL) {
    aaa = tr_aaa_server_from_string(mem_ctx, s);
    free(s);
  }
  return aaa;
}

TR_AAA_SERVER_ITER *tr_aaa_server_iter_new(TALLOC_CTX *mem_ctx)
{
  return talloc(mem_ctx, TR_AAA_SERVER_ITER);
}

void tr_aaa_server_iter_free(TR_AAA_SERVER_ITER *iter)
{
  talloc_free(iter);
}

TR_AAA_SERVER *tr_aaa_server_iter_first(TR_AAA_SERVER_ITER *iter, TR_AAA_SERVER *aaa)
{
  iter->this=aaa;
  return iter->this;
}

TR_AAA_SERVER *tr_aaa_server_iter_next(TR_AAA_SERVER_ITER *iter)
{
  if (iter->this!=NULL) {
    iter->this=iter->this->next;
  }
  return iter->this;
}
