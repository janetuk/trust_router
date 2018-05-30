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

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include <tr_inet_util.h>

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
 * Determine whether a string is a valid IPv4 address
 * @param s string to validate
 * @return 1 if a valid reference, 0 otherwise
 */
int is_valid_ipv4_address(const char *s)
{
  return is_valid_address(AF_INET, s);
}

/**
 * Determine whether a string is a valid IPv6 address reference
 *
 * I.e., an IPv6 address in brackets
 *
 * @param s string to validate
 * @return 1 if a valid reference, 0 otherwise
 */
int is_valid_ipv6_reference(const char *s)
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
  cpy = strndup(s+1, len-2);
  if (cpy == NULL)
    return -1;

  valid_ipv6 = is_valid_address(AF_INET6, cpy);
  free(cpy);

  return valid_ipv6;
}

static int is_valid_dns_char(char c)
{
  /* digits ok */
  if ( ('0' <= c) && ('9' >= c))
    return 1;

  /* letters ok */
  if ( (('a' <= c) && ('z' >= c))
       || (('A' <= c) && ('Z' >= c)) )
    return 1;

  /* '-' ok */
  if ('-' == c)
    return 1;

  /* everything else illegal */
  return 0;
}

/**
 * Helper to validate a DNS label
 *
 * Checks whether the string starting at s[start] and ending at s[end-1]
 * is a valid DNS label.
 *
 * Does not check the length of the label.
 *
 * @param s
 * @param start
 * @param end
 * @return
 */
static int is_valid_dns_label(const char *s, size_t start, size_t end)
{
  size_t ii;

  /* Check that there is at least one character.
   * Be careful - size_t is unsigned */
  if (start >= end)
    return 0;

  /* must neither start nor end with '-' */
  if ((s[start] == '-')
      || s[end-1] == '-')
    return 0;

  /* make sure all characters are valid */
  for (ii=start; ii<end; ii++) {
    if (! is_valid_dns_char(s[ii]))
      return 0;
  }

  return 1;
}

/**
 * Determine whether a string is a valid DNS name
 *
 * Does not check the length of the name or of the indivdiual
 * labels in it.
 *
 * @param s string to validate
 * @return 1 if a valid DNS name, 0 otherwise
 */
int is_valid_dns_name(const char *s)
{
  size_t label_start;
  size_t label_end;

  /* reject some trivial cases */
  if ((s == NULL)
      || (*s == '\0'))
    return 0;

  /* Walk along with the end counter until we encounter a '.'. When that
   * happens, we have a complete DNS label. Validate that, then set the start
   * counter to one character past the end pointer, which will either be the
   * next character in the DNS name or the null terminator. Since we stop as
   * soon as the end counter reaches a null character, this will never refer
   * to an invalid address. */
  for (label_start = 0, label_end = 0;
       s[label_end] != '\0';
       label_end++) {
    if (s[label_end] == '.') {
      if (! is_valid_dns_label(s, label_start, label_end))
        return 0;

      label_start = label_end+1;
    }
  }

  if (s[label_start] == '\0')
    return 1; /* we must have ended on a '.' */

  /* There was one more label to validate */
  return is_valid_dns_label(s, label_start, label_end);
}

/**
 * Validate a host string
 *
 * Valid formats:
 *   IPv4 address (dotted quad)
 *   IPv6 address in brackets (e.g., [::1])
 *   DNS hostname (labels made of alphanumerics or "-", separated by dots)
 *
 * @param s string to validate
 * @return 1 if a valid host specification, 0 otherwise
 */
int is_valid_host(const char *s)
{
  if (is_valid_ipv4_address(s))
    return 1;

  if (is_valid_ipv6_reference(s))
    return 1;

  if (is_valid_dns_name(s))
    return 1;

  return 0;
}
