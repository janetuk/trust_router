/*
 * Copyright (c) 2012, JANET(UK)
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

#include <gsscon.h>
#include <assert.h>

static int cb_print_names(gss_name_t clientName,
			  gss_buffer_t displayName,
			  void *data)
{
  assert(clientName != NULL);
  assert(data == NULL);
  printf("Gss name: %-*s\n",
	 displayName->length, displayName->value);
  return 0;
}

  
/* --------------------------------------------------------------------------- */

static int SetupListeningSocket (int  inPort, 
                                 int *outFD)
{
    int err = 0;
    int fd = -1;
    
    if (!outFD) { err = EINVAL; }
    
    if (!err) {
        fd = socket (AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { err = errno; }
    }
    
    if (!err) {
        struct sockaddr_storage addressStorage;
        struct sockaddr_in *saddr = (struct sockaddr_in *) &addressStorage;
        
        saddr->sin_port = htons (inPort);
	//        saddr->sin_len = sizeof (struct sockaddr_in);
        saddr->sin_family = AF_INET;
        saddr->sin_addr.s_addr = INADDR_ANY;
        
        err = bind (fd, (struct sockaddr *) saddr, sizeof(struct sockaddr_in));
        if (err < 0) { err = errno; }
    }
    
    if (!err) {
        err = listen (fd, 5);
        if (err < 0) { err = errno; }
    }
    
    if (!err) {
        printf ("listening on port %d\n", inPort);
        *outFD = fd;
        fd = -1; /* only close on error */
    } else {
        gsscon_print_error (err, "SetupListeningSocket failed");
    }
    
    if (fd >= 0) { close (fd); }
    
    return err; 
}

/* --------------------------------------------------------------------------- */

static void Usage (const char *argv[])
{
    fprintf (stderr, "Usage: %s [--port portNumber] [--service serviceName]\n", 
             argv[0]);
    exit (1);
}

/* --------------------------------------------------------------------------- */

int main (int argc, const char *argv[])
{
    int err = 0;
    OM_uint32 minorStatus;
    int port = kDefaultPort;
    int listenFD = -1;
    gss_ctx_id_t gssContext = GSS_C_NO_CONTEXT;
    int i = 0;
        
    for (i = 1; (i < argc) && !err; i++) {
        if ((strcmp (argv[i], "--port") == 0) && (i < (argc - 1))) {
            port = strtol (argv[++i], NULL, 0);
            if (port == 0) { err = errno; }
        } else if ((strcmp(argv[i], "--service") == 0) && (i < (argc - 1))) {
            gServiceName = argv[++i];
        } else {
            err = EINVAL;
        }
    }

    if (!err) {
        printf ("%s: Starting up...\n", argv[0]);
        
        err = SetupListeningSocket (port, &listenFD);
    }
    
    while (!err) {
        int connectionErr = 0;
        int connectionFD = -1;
        int authorized = 0;
        int authorizationError = 0;
        
        connectionFD = accept (listenFD, NULL, NULL);

        if (connectionFD < 0) {
            if (errno != EINTR) { 
                err = errno;
            }
            continue;  /* Try again */
        }
        
        printf ("Accepting new connection...\n");
        connectionErr = gsscon_passive_authenticate (connectionFD, &gssContext,
						     cb_print_names, NULL);
        
        if (!connectionErr) {
            connectionErr = gsscon_authorize (gssContext, 
                                       &authorized, 
                                       &authorizationError);
        }
        
        if (!connectionErr) {
            char buffer[1024];
            memset (buffer, 0, sizeof (buffer));                

            /* 
             * Here is where your protocol would go.  This sample server just
             * writes a nul terminated string to the client telling whether 
             * it was authorized.
             */
            if (authorized) {
                snprintf (buffer, sizeof (buffer), "SUCCESS!"); 
            } else {
                snprintf (buffer, sizeof(buffer), "FAILURE! %s (err = %d)", 
                          error_message (authorizationError), 
                          authorizationError); 
            }
            connectionErr = gsscon_write_encrypted_token (connectionFD, gssContext, 
                                                 buffer, strlen (buffer) + 1);
        }
        
        if (connectionErr) {
            gsscon_print_error (connectionErr, "Connection failed");
        }
        
        if (connectionFD >= 0) { 
            printf ("Closing connection.\n"); 
            close (connectionFD); 
        }
    }
    
    if (err) { 
        if (err == EINVAL) {
            Usage (argv);
        } else {
            gsscon_print_error (err, "Server failed");
        }
    }
    
    if (listenFD >= 0) { close (listenFD); }
    if (gssContext != GSS_C_NO_CONTEXT) { 
        gss_delete_sec_context (&minorStatus, &gssContext, GSS_C_NO_BUFFER); }
    
    return err ? -1 : 0;
}

