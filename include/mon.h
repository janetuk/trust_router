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


#ifndef TRUST_ROUTER_MON_H
#define TRUST_ROUTER_MON_H

#include <gssapi.h>
#include <trust_router/tr_name.h>

/* Typedefs */
typedef struct mon_req MON_REQ;
typedef struct mon_resp MON_RESP;

typedef enum mon_cmd MON_CMD;
typedef enum mon_resp_code MON_RESP_CODE;

typedef struct mon_opt MON_OPT;
typedef enum mon_opt_type MON_OPT_TYPE;

typedef enum mon_rc MON_RC;

typedef struct mons_instance MONS_INSTANCE;
typedef struct monc_instance MONC_INSTANCE;

typedef struct mons_dispatch_table_entry MONS_DISPATCH_TABLE_ENTRY;

typedef int (MONS_REQ_FUNC)(MONS_INSTANCE *, MON_REQ *, MON_RESP *, void *);
typedef int (MONS_AUTH_FUNC)(gss_name_t client_name, TR_NAME *display_name, void *cookie);
typedef int (MONC_RESP_FUNC)(MONS_INSTANCE *, MON_REQ *, MON_RESP *, void *);

#endif //TRUST_ROUTER_MON_H
