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

/* --------------------------------------------------------------------------- */
/* Display the contents of the buffer in hex and ascii                         */

static void PrintBuffer (const char *inBuffer, 
                         size_t      inLength)
{
    int i;  
    
    for (i = 0; i < inLength; i += 16) {
        int l;
        for (l = i; l < (i + 16); l++) {
            if (l >= inLength) {
                printf ("  ");
            } else {
                u_int8_t *byte = (u_int8_t *) inBuffer + l;
                printf ("%2.2x", *byte);
            }
            if ((l % 4) == 3) { printf (" "); }
        }
        printf ("   ");
        for (l = i; l < (i + 16) && l < inLength; l++) {
            printf ("%c", ((inBuffer[l] > 0x1f) && 
                           (inBuffer[l] < 0x7f)) ? inBuffer[l] : '.');            
        }
        printf ("\n");
    }
    printf ("\n");
}

/* --------------------------------------------------------------------------- */
/* Standard network read loop, accounting for EINTR, EOF and incomplete reads  */

static int ReadBuffer (int     inSocket, 
                       size_t  inBufferLength, 
                       char   *ioBuffer)
{
    int err = 0;
    ssize_t bytesRead = 0;
    
    if (!ioBuffer) { err = EINVAL; }
    
    if (!err) {
        char *ptr = ioBuffer;
        do {
            ssize_t count = read (inSocket, ptr, inBufferLength - bytesRead);
            if (count < 0) {
                /* Try again on EINTR */
                if (errno != EINTR) { err = errno; }
            } else if (count == 0) {
                err = ECONNRESET; /* EOF and we expected data */
            } else {
                ptr += count;
                bytesRead += count;
            }
        } while (!err && (bytesRead < inBufferLength));
    } 
    
    if (err) { gsscon_print_error (err, "ReadBuffer failed"); }

    return err;
}

/* --------------------------------------------------------------------------- */
/* Standard network write loop, accounting for EINTR and incomplete writes     */

static int WriteBuffer (int         inSocket, 
                        const char *inBuffer, 
                        size_t      inBufferLength)
{
    int err = 0;
    ssize_t bytesWritten = 0;
    
    if (!inBuffer) { err = EINVAL; }
    
    if (!err) {
        const char *ptr = inBuffer;
        do {
            ssize_t count = write (inSocket, ptr, inBufferLength - bytesWritten);
            if (count < 0) {
                /* Try again on EINTR */
                if (errno != EINTR) { err = errno; }
            } else {
                ptr += count;
                bytesWritten += count;
            }
        } while (!err && (bytesWritten < inBufferLength));
    } 
    
    if (err) { gsscon_print_error (err, "WritBuffer failed"); }

    return err;
}

/* --------------------------------------------------------------------------- */
/* Read a GSS token (length + data) off the network                            */

int gsscon_read_token (int      inSocket, 
               char   **outTokenValue, 
               size_t  *outTokenLength)
{
    int err = 0;
    char *token = NULL;
    u_int32_t tokenLength = 0;
    
    if (!outTokenValue ) { err = EINVAL; }
    if (!outTokenLength) { err = EINVAL; }
    
    if (!err) {
        err = ReadBuffer (inSocket, 4, (char *) &tokenLength);
    }
    
    if (!err) {
	tokenLength = ntohl (tokenLength);
	token = malloc (tokenLength);
	memset (token, 0, tokenLength); 
        
	err = ReadBuffer (inSocket, tokenLength, token);
    }
    
    if (!err) {
        printf ("Read token:\n");
        PrintBuffer (token, tokenLength);
        
	*outTokenLength = tokenLength;
        *outTokenValue = token;        
        token = NULL; /* only free on error */
    } else { 
        gsscon_print_error (err, "ReadToken failed"); 
    }

    if (token) { free (token); }
    
    return err;
}

/* --------------------------------------------------------------------------- */
/* Write a GSS token (length + data) onto the network                          */

int gsscon_write_token (int         inSocket, 
                const char *inTokenValue, 
                size_t      inTokenLength)
{
    int err = 0;
    u_int32_t tokenLength = htonl (inTokenLength);

    if (!inTokenValue) { err = EINVAL; }
    
    if (!err) {
	err = WriteBuffer (inSocket, (char *) &tokenLength, 4);
    }
        
    if (!err) { 
        err = WriteBuffer (inSocket, inTokenValue, inTokenLength);
    }
    
    if (!err) {
        printf ("Wrote token:\n");
        PrintBuffer (inTokenValue, inTokenLength);
    } else { 
        gsscon_print_error (err, "gsscon_write_token() failed");
    }
   
    return err;
}

/* --------------------------------------------------------------------------- */
/* Read an encrypted GSS token (length + encrypted data) off the network       */


int gsscon_read_encrypted_token (int                  inSocket, 
                        const gss_ctx_id_t   inContext, 
                        char               **outTokenValue, 
                        size_t              *outTokenLength)
{
    int err = 0;
    char *token = NULL;
    size_t tokenLength = 0;
    OM_uint32 majorStatus;
    OM_uint32 minorStatus = 0;
    gss_buffer_desc outputBuffer = { 0 , NULL};
    char *unencryptedToken = NULL;
    
    if (!inContext     ) { err = EINVAL; }
    if (!outTokenValue ) { err = EINVAL; }
    if (!outTokenLength) { err = EINVAL; }
    
    if (!err) {
        err = gsscon_read_token (inSocket, &token, &tokenLength);
    }
    
    if (!err) {
        gss_buffer_desc inputBuffer = { tokenLength, token};
        int encrypted = 0; /* did mechanism encrypt/integrity protect? */

        majorStatus = gss_unwrap (&minorStatus, 
                                  inContext, 
                                  &inputBuffer, 
                                  &outputBuffer, 
                                  &encrypted, 
                                  NULL /* qop_state */);
        if (majorStatus != GSS_S_COMPLETE) { 
            gsscon_print_gss_errors("gss_unwrap", majorStatus, minorStatus);
            err = minorStatus ? minorStatus : majorStatus; 
        } else if (!encrypted) {
            fprintf (stderr, "WARNING!  Mechanism not using encryption!");
            err = EINVAL; /* You may not want to fail here. */
        }
    }
    
    if (!err) {
        unencryptedToken = malloc (outputBuffer.length);
        if (unencryptedToken == NULL) { err = ENOMEM; }
    }
    
    if (!err) {
        memcpy (unencryptedToken, outputBuffer.value, outputBuffer.length);
        
        printf ("Unencrypted token:\n");
        PrintBuffer (unencryptedToken, outputBuffer.length);
        
	*outTokenLength = outputBuffer.length;
        *outTokenValue = unencryptedToken;
        unencryptedToken = NULL; /* only free on error */
        
    } else { 
        gsscon_print_error (err, "ReadToken failed"); 
    }
    
    if (token             ) { free (token); }
    if (outputBuffer.value) { gss_release_buffer (&minorStatus, &outputBuffer); }
    if (unencryptedToken  ) { free (unencryptedToken); }
    
    return err;
}

/* --------------------------------------------------------------------------- */
/* Write an encrypted GSS token (length + encrypted data) onto the network     */

int gsscon_write_encrypted_token (int                 inSocket, 
                         const gss_ctx_id_t  inContext, 
                         const char         *inToken, 
                         size_t              inTokenLength)
{
    int err = 0;
    OM_uint32 majorStatus;
    OM_uint32 minorStatus = 0;
    gss_buffer_desc outputBuffer = { 0, NULL };
    
    if (!inContext) { err = EINVAL; }
    if (!inToken  ) { err = EINVAL; }
    
    if (!err) {
        gss_buffer_desc inputBuffer = { inTokenLength, (char *) inToken };
        int encrypt = 1;   /* do encryption and integrity protection */
        int encrypted = 0; /* did mechanism encrypt/integrity protect? */
        
        majorStatus = gss_wrap (&minorStatus, 
                                inContext, 
                                encrypt, 
                                GSS_C_QOP_DEFAULT,
                                &inputBuffer, 
                                &encrypted, 
                                &outputBuffer);
        if (majorStatus != GSS_S_COMPLETE) { 
            gsscon_print_gss_errors ("gss_wrap", majorStatus, minorStatus);
            err = minorStatus ? minorStatus : majorStatus; 
        } else if (!encrypted) {
            fprintf (stderr, "WARNING!  Mechanism does not support encryption!");
            err = EINVAL; /* You may not want to fail here. */
        }
    }
    
    if (!err) {
        printf ("Unencrypted token:\n");
        PrintBuffer (inToken, inTokenLength);
	err = gsscon_write_token (inSocket, outputBuffer.value, outputBuffer.length);
    }
    
    if (!err) {
    } else { 
        gsscon_print_error (err, "gsscon_write_token failed");
    }
    
    if (outputBuffer.value) { gss_release_buffer (&minorStatus, &outputBuffer); }
    
    return err;
}

/* --------------------------------------------------------------------------- */
/* Print BSD error                                                             */

void gsscon_print_error (int         inError, 
                 const char *inString)
{
    fprintf (stderr, "%s: %s (err = %d)\n", 
             inString, error_message (inError), inError);
}

/* --------------------------------------------------------------------------- */
/* PrintGSSAPI errors                                                         */

void gsscon_print_gss_errors (const char *inRoutineName, 
                     OM_uint32   inMajorStatus, 
                     OM_uint32   inMinorStatus)
{
    OM_uint32 minorStatus;
    OM_uint32 majorStatus;	
    gss_buffer_desc errorBuffer;

    OM_uint32 messageContext = 0; /* first message */
    int count = 1;
    
    fprintf (stderr, "Error returned by %s:\n", inRoutineName);
    
    do {
        majorStatus = gss_display_status (&minorStatus, 
                                          inMajorStatus, 
                                          GSS_C_GSS_CODE, 
                                          GSS_C_NULL_OID, 
                                          &messageContext, 
                                          &errorBuffer);
        if (majorStatus == GSS_S_COMPLETE) {
            fprintf (stderr,"      major error <%d> %s\n", 
                     count, (char *) errorBuffer.value);
            gss_release_buffer (&minorStatus, &errorBuffer);
        }
        ++count;
    } while (messageContext != 0);
    
    count = 1;
    messageContext = 0;
    do {
        majorStatus = gss_display_status (&minorStatus, 
                                          inMinorStatus, 
                                          GSS_C_MECH_CODE, 
                                          GSS_C_NULL_OID, 
                                          &messageContext, 
                                          &errorBuffer);
        fprintf (stderr,"      minor error <%d> %s\n", 
                 count, (char *) errorBuffer.value);
        ++count;
    } while (messageContext != 0);
}

