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

#ifndef _TR_DEBUG_H
#define _TR_DEBUG_H

#include <syslog.h>
#include <trust_router/tr_versioning.h>
#include <tid_internal.h>

/* Log macros according to severity levels */

#define tr_emerg(...)   tr_log(LOG_EMERG, __VA_ARGS__)
#define tr_alert(...)   tr_log(LOG_ALERT, __VA_ARGS__)
#define tr_crit(...)    tr_log(LOG_CRIT, __VA_ARGS__)
#define tr_err(...)     tr_log(LOG_ERR, __VA_ARGS__)
#define tr_warning(...) tr_log(LOG_WARNING, __VA_ARGS__)
#define tr_notice(...)  tr_log(LOG_NOTICE, __VA_ARGS__)
#define tr_info(...)    tr_log(LOG_INFO, __VA_ARGS__)
#define tr_debug(...)   tr_log(LOG_DEBUG, __VA_ARGS__)

TR_EXPORT const char *sev2str(int sev);
TR_EXPORT int str2sev(const char *sev);
TR_EXPORT void tr_log_threshold(const int sev);
TR_EXPORT void tr_console_threshold(const int sev);
TR_EXPORT void tr_log_open(void);
TR_EXPORT void tr_log_close(void);
TR_EXPORT void tr_log(const int sev, const char *fmt, ...);
TR_EXPORT void tr_audit_resp(TID_RESP *resp);
TR_EXPORT void tr_audit_req(TID_REQ *req);

#endif
