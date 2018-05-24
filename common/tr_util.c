/*
 * Copyright (c) 2012, 2013, JANET(UK)
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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <tr_name_internal.h>
#include <tr_util.h>
#include <stdlib.h>
#include <talloc.h>

void tr_bin_to_hex(const unsigned char * bin, size_t bin_len,
		   char * hex_out, size_t hex_len)
{
  assert(hex_len >= 2*bin_len);
  while (bin_len >0) {
    snprintf(hex_out, hex_len, "%.2x", bin[0]);
    bin++, hex_out += 2;
    bin_len--;
    hex_len -= 2;
  }
}

/**
 * Compare two timespecs
 *
 * Assumes tv_nsec <= 1e9
 *
 * @param ts1
 * @param ts2
 * @return 0 if ts1==ts2, -1 if ts1<ts2, 1 if ts1>ts2.
 */
int tr_cmp_timespec(const struct timespec *ts1, const struct timespec *ts2)
{
  if (ts1->tv_sec > ts2->tv_sec)
    return 1;

  if (ts1->tv_sec < ts2->tv_sec)
    return -1;

  /* ts1->tv_sec==ts2->tv_sec */

  if (ts1->tv_nsec > ts2->tv_nsec)
    return 1;

  if (ts1->tv_nsec < ts2->tv_nsec)
    return -1;

  return 0;
}

/**
 * Compute ts1 + ts2
 *
 * @param ts1
 * @param ts2
 * @param sum ts1 + ts2
 * @return 0 on success, nonzero on error
 */
int tr_add_timespec(const struct timespec *ts1, const struct timespec *ts2, struct timespec *sum)
{
  const time_t ONE_BILLION = 1000000000;

  if (!ts1 || !ts2 || !sum)
    return -1;

  /* would be nice to do range checking, but I don't know a portable way to get the
   * max value of a time_t. Figure that nsec <= 1e9 and seconds are unlikely to go off
   * too close to infinity, so overflow is unlikely */
  sum->tv_nsec = ts1->tv_nsec + ts2->tv_nsec;
  sum->tv_sec = ts1->tv_sec + ts2->tv_sec;

  /* make sure that we have no more than a second worth of nsec */
  while (sum->tv_nsec >= ONE_BILLION) {
    sum->tv_nsec -= ONE_BILLION;
    sum->tv_sec += 1;
  }

  return 0;
}

/**
 * Compute ts1 - ts2
 *
 * Allows negative results, which will be represented as a negative tv_sec.
 * The returned tv_nsec is always positive and less than 1e9.
 *
 * (The value represented is tv_sec + tv_nsec/1e9 seconds - this is a little
 * counterintuitive when tv_sec is negative. E.g., -1.5 seconds is represented
 * as {-2, 500000000). Negative time_t values are not guaranteed to be supported
 * anyway, so it's probably best to stay away from them.)
 *
 * @param ts1
 * @param ts2
 * @param diff ts1 - ts2
 * @return 0 on success, nonzero on error
 */
int tr_sub_timespec(const struct timespec *ts1, const struct timespec *ts2, struct timespec *diff)
{
  const time_t ONE_BILLION = 1000000000;
  struct timespec ts1_copy = {0};
  struct timespec ts2_copy = {0};
  
  if (!ts1 || !ts2 || !diff)
    return -1;

  ts1_copy = *ts1;
  ts2_copy = *ts2;
  
  while (ts2_copy.tv_nsec > ts1_copy.tv_nsec) {
    /* Reduce ts2 by one second worth of nsec, balanced by removing a second
     * from ts1. Repeat until ts2->tv_nsec <= ts1->tv_nsec. */
    ts2_copy.tv_nsec -= ONE_BILLION;
    ts1_copy.tv_sec -= 1;
  }

  diff->tv_nsec = ts1_copy.tv_nsec - ts2_copy.tv_nsec; /* >= 0 */
  diff->tv_sec = ts1_copy.tv_sec - ts2_copy.tv_sec; /* sign indeterminate */

  /* make sure we have no more than 1 sec worth of nsec */
  while (diff->tv_nsec > ONE_BILLION) {
    diff->tv_nsec -= ONE_BILLION;
    diff->tv_sec += 1;
  }

  return 0;
}

/**
 * Convert a struct timespec to a string representation
 * @param ts
 * @return
 */
char *timespec_to_str(const struct timespec *ts)
{
  struct tm tm;
  char *s=NULL;

  if (gmtime_r(&(ts->tv_sec), &tm)==NULL)
    return NULL;

  s=malloc(40); /* long enough to contain strftime result */
  if (s==NULL)
    return NULL;

  if (strftime(s, 40, "%F %T UTC", &tm)==0) {
    free(s);
    return NULL;
  }
  return s;
}

/**
 * Convert a time from one clock to another
 *
 * Because this involves reading each clock, it is not exact.
 *
 * @param from clock to convert from
 * @param when time to convert, measured on the 'from' clock
 * @param to clock to convert to
 * @param dst destination, measured on the 'to' clock
 * @return dst or null on error
 */
struct timespec *tr_clock_convert(clockid_t from, const struct timespec *when,
                                  clockid_t to, struct timespec *dst)
{
  struct timespec now_from = {0};
  struct timespec diff = {0}; /* difference between when and now_from */
  struct timespec now_to = {0};

  if ((clock_gettime(from, &now_from) != 0)
      || (clock_gettime(to, &now_to) != 0)) {
    return NULL;
  }
  if (tr_sub_timespec(when, &now_from, &diff) != 0) {
    return NULL;
  }
  if (tr_add_timespec(&now_to, &diff, dst) != 0) {
    return NULL;
  }
  return dst;
}

TR_NAME *tr_parse_hostname(const char *s)
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
 * Parse the port from a hostname:port string
 *
 * @param s string to parse
 * @return the specified port, 0 if none specified, -1 if invalid
 */
int tr_parse_port(const char *s)
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
 * Parse hostname and port
 *
 * @param s
 * @param hn_dest
 * @param p_dest
 * @return 0 on success, -1 on error
 */
int tr_parse_hostname_and_port(const char *s, TR_NAME **hn_dest, int *p_dest)
{
  if ((hn_dest == NULL) || (p_dest == NULL))
    return -1;

  *hn_dest = tr_parse_hostname(s);
  if (*hn_dest == NULL)
    return -1;

  *p_dest = tr_parse_port(s);
  if ((*p_dest < 0) || (*p_dest > 65535)) {
    tr_free_name(*hn_dest);
    *hn_dest = NULL;
    return -1;
  }

  return 0;
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
