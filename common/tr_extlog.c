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
#include <trust_router/tr_extlog.h>
#include <tid_internal.h>

#define EXTLOG_PREFIX "F-TICKS/abfab/1.0"
#define EXTLOG_MAX_MESSAGE_SIZE 65536
#define EXTLOG_FIELD_SEP "#"
#define EXTLOG_MSG_TERMINATOR "#"
#define EXTLOG_KV_SEP "="
#define EXTLOG_OVERHEAD strlen(EXTLOG_PREFIX)

static unsigned int tr_extlog_enabled;
static unsigned int tr_extlog_opened = 0;

static void fire_extlog(const int pri, const char *msg) {

  syslog(pri, "%s%s%s", EXTLOG_PREFIX, msg, EXTLOG_MSG_TERMINATOR);
}

static char *extlog_fmt(const char *key, char *value) {

  if (NULL != key) {

    /* Rewrite any NULL's to "nones" */
    char *val = NULL == value ? "none" : value;

    size_t len = strlen(key)
               + strlen(val)
               + strlen(EXTLOG_FIELD_SEP)
               + strlen(EXTLOG_KV_SEP)
               + 1;

    char *buf = malloc(len);

    snprintf(buf, len, "%s%s%s%s", EXTLOG_FIELD_SEP, key, EXTLOG_KV_SEP, val);

    return buf;
  }
  else {

    fprintf(stderr, "extlog_fmt: Message dropped, null pointer passed.\n");
    return NULL;
  }
}

static void extlog_free_array(const int count, char *array[]) {

   int i;

   for(i = 0; i < count; i++) {
      free(array[i]);
   }
}

static char *extlog_join_msg(const int count, char *array[]) {

  int i;
  int len = 1; /* start at one to account for terminator */

  /* evaluate length of concatenated string */
  for(i = 0; i < count; i++) {

    if ((len + strlen(array[i]) + EXTLOG_OVERHEAD) <= EXTLOG_MAX_MESSAGE_SIZE) {

      len += strlen(array[i]);
    }
  }

  int remain = len - 1;
  char *buf = (char *) calloc(len, sizeof(char *));

  /* join fields up to count */
  for(i = 0; i < count; i++) {

    if ((strlen(buf) + strlen(array[i]) + EXTLOG_OVERHEAD + 1) <= EXTLOG_MAX_MESSAGE_SIZE) {

      strncat(buf, array[i], remain);
      remain -= strlen(array[i]);
    }
    else {

      fprintf(stderr, "extlog_join_message: Attribute dropped, too long.\n");
    }
  }

  return buf;
}

void tr_extlog_enable() {

  tr_extlog_enabled = 1;
  return;
}

void tr_extlog_disable() {

  tr_extlog_close();
  tr_extlog_enabled = 0;
  return;
}

int tr_extlog_open() {

  if (tr_extlog_enabled && !tr_extlog_opened) {

    openlog(NULL, LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
    tr_extlog_opened = 1;
  }

  return tr_extlog_opened;
}

void tr_extlog_close() {

  if (tr_extlog_enabled) {

    closelog();
    tr_extlog_opened = 0;
  }
}

void tr_extlog_resp(TID_RESP *resp) {

  if (tr_extlog_enabled && tr_extlog_open()) {
    if (NULL != resp) {

      char *attrs[] = { extlog_fmt("result", resp->result ? "error" : "success"),
                        extlog_fmt("comm", NULL != resp->comm ? resp->comm->buf : NULL),
                        extlog_fmt("rp_realm", NULL != resp->rp_realm ? resp->rp_realm->buf : NULL),
                        extlog_fmt("realm", NULL != resp->realm ? resp->realm->buf : NULL),
                        extlog_fmt("err", NULL != resp->err_msg ? resp->err_msg->buf : NULL)
                      };

      char *msg = extlog_join_msg(sizeof(attrs) / sizeof(attrs[0]), attrs);
      extlog_free_array(sizeof(attrs) / sizeof(attrs[0]), attrs);

      fire_extlog(LOG_NOTICE, msg);

      free(msg);
    }
    else {

      fprintf(stderr, "tr_extlog_resp: Message dropped, null pointer passed.\n");
    }
  }
}

void tr_extlog_req(TID_REQ *req) {

  if (tr_extlog_enabled && tr_extlog_open()) {
    if (NULL != req) {

      char *attrs[] = { extlog_fmt("comm", NULL != req->comm ? req->comm->buf : NULL),
                        extlog_fmt("rp_realm", NULL != req->rp_realm ? req->rp_realm->buf : NULL),
                        extlog_fmt("realm", NULL != req->realm ? req->realm->buf : NULL),
                      };

      char *msg = extlog_join_msg(sizeof(attrs) / sizeof(attrs[0]), attrs);
      extlog_free_array(sizeof(attrs) / sizeof(attrs[0]), attrs);

      fire_extlog(LOG_NOTICE, msg);

      free(msg);
    }
    else {

          fprintf(stderr, "tr_extlog_req: Message dropped, null pointer passed.\n");
    }
  }
}

void tr_extlog_simple(const char *fmt, ...) {

  if (tr_extlog_enabled && tr_extlog_open()) {
    if (NULL != fmt) {

      char *buf = malloc(EXTLOG_MAX_MESSAGE_SIZE);

      va_list ap;
      va_start(ap, fmt);

      vsnprintf(buf, EXTLOG_MAX_MESSAGE_SIZE, fmt, ap);

      char *msg = extlog_fmt("msg", buf);

      fire_extlog(LOG_NOTICE, msg);

      free(msg);
      free(buf);
    }
    else {

          fprintf(stderr, "tr_extlog_simple: Message dropped, null pointer passed.\n");
    }
  }
}
