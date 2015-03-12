/*
 * Copyright (c) 2014, JANET(UK)
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

#include <stdlib.h>
#include <syslog.h>
#include <tr_debug.h>
#include <tid_internal.h>

#define LOG_MAX_MESSAGE_SIZE 65536
#define LOG_FACILITY LOG_LOCAL5

#define LOG_PREFIX "F-TICKS/abfab/1.0"
#define LOG_OVERHEAD strlen(LOG_PREFIX)
#define LOG_FIELD_SEP "#"
#define LOG_MSG_TERMINATOR "#"
#define LOG_KV_SEP "="
#define AUDIT_FACILITY LOG_AUTHPRIV

static int log_opened = 0;

/* We'll be noisy until overriden */
static int log_threshold = LOG_DEBUG;
static int console_threshold = LOG_DEBUG;

static void vfire_log(const int sev, const int facility, const char *fmt, va_list ap) {

   /* if we want to use ap twice, we need to duplicate it before the first use */
   va_list ap_copy;
   va_copy(ap_copy, ap);

  /* write messages to stderr if they are more severe than the threshold and are not audit messages */
  if ((sev <= console_threshold) && (facility != AUDIT_FACILITY)) {

    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
  }

  /* write messages to syslog if they are more severe than the threshold or are audit messages */
  if (sev <= log_threshold || (facility == AUDIT_FACILITY)) {

    /* Make sure that the message will fit, truncate if necessary */
    char *buf = malloc(LOG_MAX_MESSAGE_SIZE);
    vsnprintf(buf, LOG_MAX_MESSAGE_SIZE, fmt, ap_copy);

    /* syslog.h provides a macro for generating priorities, however in versions of glibc < 2.17 it is
       broken if you use it as documented: https://sourceware.org/bugzilla/show_bug.cgi?id=14347
       RHEL6 uses glibc 2.12, so do not use LOG_MAKEPRI until around 2020.
    */
    syslog((facility|sev), "%s", buf);

    free(buf);
  }

  va_end(ap_copy);
}

static void fire_log(const int sev, const int facility, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfire_log(sev, facility, fmt, ap);
  va_end(ap);
}

static char *audit_fmt(const char *key, char *value) {

  if (NULL != key) {

    /* Rewrite any NULL's to "nones" */
    char *val = NULL == value ? "none" : value;

    size_t len = strlen(key)
               + strlen(val)
               + strlen(LOG_FIELD_SEP)
               + strlen(LOG_KV_SEP)
               + 1;

    char *buf = malloc(len);

    snprintf(buf, len, "%s%s%s%s", LOG_FIELD_SEP, key, LOG_KV_SEP, val);

    return buf;
  }
  else {

    tr_debug("audit_fmt: Message dropped, null pointer passed.");
    return NULL;
  }
}

static void free_array(const int count, char *array[]) {

   int i;

   for(i = 0; i < count; i++) {
      free(array[i]);
   }
}

static char *join_audit_msg(const int count, char *array[]) {

  int i;
  int len = 1; /* start at one to account for terminator */

  /* evaluate length of concatenated string */
  for(i = 0; i < count; i++) {

    if ((len + strlen(array[i]) + LOG_OVERHEAD) <= LOG_MAX_MESSAGE_SIZE) {

      len += strlen(array[i]);
    }
  }

  int remain = len - 1;
  char *buf = (char *) calloc(len, sizeof(char));

  /* join fields up to count */
  for(i = 0; i < count; i++) {

    if ((strlen(buf) + strlen(array[i]) + LOG_OVERHEAD + 1) <= LOG_MAX_MESSAGE_SIZE) {

      strncat(buf, array[i], remain);
      remain -= strlen(array[i]);
    }
    else {

      tr_debug("join_audit_msg: Attribute dropped, too long.");
    }
  }

  return buf;
}

int str2sev(const char* sev) {

  if (strcmp(sev, "debug") ==0 ) {

    return LOG_DEBUG;
  }
  else if (strcmp(sev, "info") == 0) {

    return LOG_INFO;
  }
  else if (strcmp(sev, "notice") == 0) {

    return LOG_NOTICE;
  }
  else if (strcmp(sev, "warning") == 0 ) {

    return LOG_WARNING;
  }
  else if (strcmp(sev, "err") == 0) {

    return LOG_ERR;
  }
  else if (strcmp(sev, "crit") == 0) {

    return LOG_CRIT;
  }
  else if (strcmp(sev, "alert") == 0) {

    return LOG_ALERT;
  }
  else if (strcmp(sev, "emerg")  == 0) {

    return LOG_EMERG;
  }

  tr_debug("str2sev: invalid severity specified: %s, logging everything", sev);

  return LOG_DEBUG;
}

void tr_log_threshold(const int sev) {

  log_threshold = sev;
  return;
}

void tr_console_threshold(const int sev) {

  console_threshold = sev;
  return;
}

void tr_log_open() {

  if (!log_opened) {

    openlog(NULL, LOG_PID | LOG_NDELAY, LOG_FACILITY);
    log_opened = 1;
  }
}

void tr_log_close() {

    closelog();
    log_opened = 0;
}

void tr_log(const int sev, const char *fmt, ...) {

  if (NULL != fmt) {

    va_list ap;
    va_start(ap, fmt);

    vfire_log(sev, LOG_FACILITY, fmt, ap);

    va_end(ap);
  }
  else {

          tr_debug("tr_log: Message dropped, null pointer passed.");
  }
}

/* Convinience Functions */

void tr_audit_resp(TID_RESP *resp) {

  if (NULL != resp) {

    char *attrs[] = { audit_fmt("result", resp->result ? "error" : "success"),
                      audit_fmt("comm", NULL != resp->comm ? resp->comm->buf : NULL),
                      audit_fmt("rp_realm", NULL != resp->rp_realm ? resp->rp_realm->buf : NULL),
                      audit_fmt("realm", NULL != resp->realm ? resp->realm->buf : NULL),
                      audit_fmt("err", NULL != resp->err_msg ? resp->err_msg->buf : NULL)
                    };

    char *msg = join_audit_msg(sizeof(attrs) / sizeof(attrs[0]), attrs);
    free_array(sizeof(attrs) / sizeof(attrs[0]), attrs);

    fire_log(LOG_INFO, AUDIT_FACILITY, "%s%s%s", LOG_PREFIX, msg, LOG_MSG_TERMINATOR);

    free(msg);
  }
  else {

    tr_debug("tr_audit_resp: Message dropped, null pointer passed.");
  }
}

void tr_audit_req(TID_REQ *req) {

  if (NULL != req) {

    char *attrs[] = { audit_fmt("comm", NULL != req->comm ? req->comm->buf : NULL),
                      audit_fmt("rp_realm", NULL != req->rp_realm ? req->rp_realm->buf : NULL),
                      audit_fmt("realm", NULL != req->realm ? req->realm->buf : NULL),
                    };

    char *msg = join_audit_msg(sizeof(attrs) / sizeof(attrs[0]), attrs);
    free_array(sizeof(attrs) / sizeof(attrs[0]), attrs);

    fire_log(LOG_INFO, AUDIT_FACILITY, "%s%s%s", LOG_PREFIX, msg, LOG_MSG_TERMINATOR);

    free(msg);
  }
  else {

        tr_debug("tr_audit_req: Message dropped, null pointer passed.");
  }
}
