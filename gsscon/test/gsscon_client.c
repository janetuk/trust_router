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

#include "../gsscon.h"

static void Usage (const char *argv[])
{
    fprintf (stderr, "Usage: %s [--port portNumber] [--server serverHostName]\n"
             "\t[--sprinc servicePrincipal] [--cprinc clientPrincipal]\n", argv[0]);
    exit (1);
}

/* --------------------------------------------------------------------------- */

int main (int argc, const char *argv[]) 
{
    int err = 0;
    int fd = -1;
    int port = kDefaultPort;
    const char *server = "127.0.0.1";
    const char *clientName = NULL;
    const char *serviceName = "host";
    gss_ctx_id_t gssContext = GSS_C_NO_CONTEXT;
    OM_uint32 minorStatus = 0;
    int i = 0;
        
    for (i = 1; (i < argc) && !err; i++) {
        if ((strcmp (argv[i], "--port") == 0) && (i < (argc - 1))) {
            port = strtol (argv[++i], NULL, 0);
            if (port == 0) { err = errno; }
        } else if ((strcmp (argv[i], "--server") == 0) && (i < (argc - 1))) {
            server = argv[++i];
        } else if ((strcmp(argv[i], "--cprinc") == 0) && (i < (argc - 1))) {
            clientName = argv[++i];
        } else if ((strcmp(argv[i], "--sprinc") == 0) && (i < (argc - 1))) {
            serviceName = argv[++i];
        } else {
            err = EINVAL;
        }
    }
    
    if (!err) {
        printf ("%s: Starting up...\n", argv[0]);
        
        err = gsscon_connect (server, port, &fd);
    }
    
    if (!err) {
        err = gsscon_active_authenticate (fd, clientName, serviceName, &gssContext);
    }
    
    if (!err) {
        char *buffer = NULL;
        size_t bufferLength = 0;

        /* 
         * Here is where your protocol would go.  This sample client just
         * reads a nul terminated string from the server.
         */
        err = gsscon_read_encrypted_token (fd, gssContext, &buffer, &bufferLength);

        if (!err) {
            printf ("Server message: '%s'\n", buffer);
        }
        
        if (buffer != NULL) { free (buffer); }
    }
    
    
    if (err) {
        if (err == EINVAL) {
            Usage (argv);
        } else {
            gsscon_print_error (err, "Client failed");
        }
    }
    
    if (fd >= 0) { printf ("Closing socket.\n"); close (fd); }
    if (gssContext != GSS_C_NO_CONTEXT) { 
        gss_delete_sec_context (&minorStatus, &gssContext, GSS_C_NO_BUFFER); }
    
    return err ? 1 : 0;
}



