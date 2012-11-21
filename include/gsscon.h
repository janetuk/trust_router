/*
 * Copyright (c) 2011, JANET(UK)
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
 * This code was adapted from the MIT Kerberos Consortium's
 * GSS example code, which was distributed under the following
 * license:
 *
 * Copyright 2004-2006 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef GSSCON_H
#define GSSCON_H

#include <sys/types.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>
#include <errno.h>

#define kDefaultPort 2000
extern const char *gServiceName;

int gsscon_read_token (int      inSocket, 
               char   **outTokenValue, 
               size_t  *outTokenLength);

int gsscon_write_token (int         inSocket, 
			const char *inTokenValue, 
			size_t      inTokenLength);

int gsscon_read_encrypted_token (int                  inSocket, 
				 const gss_ctx_id_t   inContext, 
				 char               **outTokenValue, 
				 size_t              *outTokenLength);

int gsscon_write_encrypted_token (int                 inSocket, 
				  const gss_ctx_id_t  inContext, 
				  const char         *inToken, 
				  size_t              inTokenLength);

void gsscon_print_error (int         inError, 
			 const char *inString);

void gsscon_print_gss_errors (const char *inRoutineName, 
			      OM_uint32   inMajorStatus, 
			      OM_uint32   inMinorStatus);

int gsscon_connect (const char *inHost, 
		    int inPort, 
		    int *outFD);

int gsscon_active_authenticate (int           inSocket, 
				const char   *inClientName, 
				const char   *inServiceName, 
				gss_ctx_id_t *outGSSContext);

int gsscon_passive_authenticate (int           inSocket, 
				 gss_ctx_id_t *outGSSContext);

int gsscon_authorize (gss_ctx_id_t  inContext, 
                      int          *outAuthorized, 
                      int          *outAuthorizationError);

#endif
