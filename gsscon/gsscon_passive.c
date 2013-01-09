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

const char *gServiceName = NULL;

int gsscon_passive_authenticate (int           inSocket, 
                         gss_ctx_id_t *outGSSContext)
{
    int err = 0;
    OM_uint32 majorStatus;
    OM_uint32 minorStatus = 0;
    gss_ctx_id_t gssContext = GSS_C_NO_CONTEXT;
    
    char *inputTokenBuffer = NULL;
    size_t inputTokenBufferLength = 0;
    gss_buffer_desc inputToken;  /* buffer received from the server */
    
    if (inSocket <  0 ) { err = EINVAL; }
    if (!outGSSContext) { err = EINVAL; }
    
    /* 
     * The main authentication loop:
     *
     * GSS is a multimechanism API.  The number of packet exchanges required to  
     * authenticatevaries between mechanisms.  As a result, we need to loop reading 
     * input tokens from the client, calling gss_accept_sec_context on the input 
     * tokens and send the resulting output tokens back to the client until we 
     * get GSS_S_COMPLETE or an error.
     *
     * When we are done, save the client principal so we can make authorization 
     * checks.
     */
    
    majorStatus = GSS_S_CONTINUE_NEEDED;
    while (!err && (majorStatus != GSS_S_COMPLETE)) {
        /* Clean up old input buffer */
        if (inputTokenBuffer != NULL) {
            free (inputTokenBuffer);
            inputTokenBuffer = NULL;  /* don't double-free */
        }
        
        err = gsscon_read_token (inSocket, &inputTokenBuffer, &inputTokenBufferLength);
        
        if (!err) {
            /* Set up input buffers for the next run through the loop */
            inputToken.value = inputTokenBuffer;
            inputToken.length = inputTokenBufferLength;
        }
        
        if (!err) {
            /* buffer to send to the server */
            gss_buffer_desc outputToken = { 0, NULL }; 
            
            /*
             * accept_sec_context does the actual work of taking the client's 
             * request and generating an appropriate reply.  Note that we pass 
             * GSS_C_NO_CREDENTIAL for the service principal.  This causes the 
             * server to accept any service principal in the server's keytab, 
             * which enables you to support multihomed hosts by having one key 
             * in the keytab for each host identity the server responds on.  
             *
             * However, since we may have more keys in the keytab than we want 
             * the server to actually use, we will need to check which service 
             * principal the client used after authentication succeeds.  See 
             * ServicePrincipalIsValidForService() for where you would put these 
             * checks.  We don't check here since if we stopped responding in the 
             * middle of the authentication negotiation, the client would get an 
             * EOF, and the user wouldn't know what went wrong.
             */
            
	    // printf ("Calling gss_accept_sec_context...\n");
            majorStatus = gss_accept_sec_context (&minorStatus, 
                                                  &gssContext, 
                                                  GSS_C_NO_CREDENTIAL, 
                                                  &inputToken, 
                                                  GSS_C_NO_CHANNEL_BINDINGS, 
                                                  NULL /* client_name */, 
                                                  NULL /* actual_mech_type */, 
                                                  &outputToken, 
                                                  NULL /* req_flags */, 
                                                  NULL /* time_rec */, 
                                                  NULL /* delegated_cred_handle */);
            
            if ((outputToken.length > 0) && (outputToken.value != NULL)) {
                /* Send the output token to the client (even on error) */
                err = gsscon_write_token (inSocket, outputToken.value, outputToken.length);
                
                /* free the output token */
                gss_release_buffer (&minorStatus, &outputToken);
            }
        }
        
        if ((majorStatus != GSS_S_COMPLETE) && (majorStatus != GSS_S_CONTINUE_NEEDED)) {
            gsscon_print_gss_errors ("gss_accept_sec_context", majorStatus, minorStatus);
            err = minorStatus ? minorStatus : majorStatus; 
        }            
    }
    
    if (!err) { 
        *outGSSContext = gssContext;
        gssContext = NULL;
    } else {
        gsscon_print_error (err, "Authenticate failed");
    }
    
    if (inputTokenBuffer) { free (inputTokenBuffer); }
    if (gssContext != GSS_C_NO_CONTEXT) { 
        gss_delete_sec_context (&minorStatus, &gssContext, GSS_C_NO_BUFFER); }
        
    return err;
}

/* --------------------------------------------------------------------------- */

static int ServicePrincipalIsValidForService (const char *inServicePrincipal)
{
    int err = 0;
    krb5_context context = NULL;
    krb5_principal principal = NULL;
    
    if (!inServicePrincipal) { err = EINVAL; }
    
    if (!err) {
        err = krb5_init_context (&context);
    }
    
    if (!err) {
        err = krb5_parse_name (context, inServicePrincipal, &principal);
    }
    
    if (!err) {
        /* 
         * Here is where we check to see if the service principal the client 
         * used is valid.  Typically we would just check that the first component 
         * is the name of the service provided by the server.  This check exists
         * to make sure the server is using the correct key in its keytab since
         * we passed GSS_C_NO_CREDENTIAL into gss_accept_sec_context().
         */
        if (gServiceName && strcmp (gServiceName, 
                                    krb5_princ_name (context, principal)->data) != 0) {
            err = KRB5KRB_AP_WRONG_PRINC;
        }
    }
    
    if (principal) { krb5_free_principal (context, principal); }
    if (context  ) { krb5_free_context (context); }
    
    return err;
}


/* --------------------------------------------------------------------------- */

static int ClientPrincipalIsAuthorizedForService (const char *inClientPrincipal)
{
    int err = 0;
    krb5_context context = NULL;
    krb5_principal principal = NULL;
    
    if (!inClientPrincipal) { err = EINVAL; }
    
    if (!err) {
        err = krb5_init_context (&context);
    }
    
    if (!err) {
        err = krb5_parse_name (context, inClientPrincipal, &principal);
    }
    
    if (!err) {
        /* 
         * Here is where the server checks to see if the client principal should 
         * be allowed to use your service. Typically it should check both the name 
         * and the realm, since with cross-realm shared keys, a user at another 
         * realm may be trying to contact your service.  
         */
        err = 0;
    }
    
    if (principal) { krb5_free_principal (context, principal); }
    if (context  ) { krb5_free_context (context); }
    
    return err;
}

/* --------------------------------------------------------------------------- */

int gsscon_authorize (gss_ctx_id_t  inContext, 
                      int          *outAuthorized, 
                      int          *outAuthorizationError)
{
    int err = 0;
    OM_uint32 majorStatus;
    OM_uint32 minorStatus = 0;
    gss_name_t clientName = NULL;
    gss_name_t serviceName = NULL;
    char *clientPrincipal = NULL;
    char *servicePrincipal = NULL;

    if (!inContext            ) { err = EINVAL; }
    if (!outAuthorized        ) { err = EINVAL; }
    if (!outAuthorizationError) { err = EINVAL; }
    
    if (!err) {
        /* Get the client and service principals used to authenticate */
        majorStatus = gss_inquire_context (&minorStatus, 
                                           inContext, 
                                           &clientName, 
                                           &serviceName, 
                                           NULL, NULL, NULL, NULL, NULL);
        if (majorStatus != GSS_S_COMPLETE) { 
            err = minorStatus ? minorStatus : majorStatus; 
        }
    }
    
    if (!err) {
        /* Pull the client principal string out of the gss name */
        gss_buffer_desc nameToken;
        
        majorStatus = gss_display_name (&minorStatus, 
                                        clientName, 
                                        &nameToken, 
                                        NULL);
        if (majorStatus != GSS_S_COMPLETE) { 
            err = minorStatus ? minorStatus : majorStatus; 
        }
        
        if (!err) {
            clientPrincipal = malloc (nameToken.length + 1);
            if (clientPrincipal == NULL) { err = ENOMEM; }
        }
        
        if (!err) {
            memcpy (clientPrincipal, nameToken.value, nameToken.length);
            clientPrincipal[nameToken.length] = '\0';
        }        

        if (nameToken.value) { gss_release_buffer (&minorStatus, &nameToken); }
    }
    
        if (!err) {
    //    /* Pull the service principal string out of the gss name */
    //    gss_buffer_desc nameToken;
    //    
    //    majorStatus = gss_display_name (&minorStatus, 
    //                                    serviceName, 
    //                                    &nameToken, 
    //                                    NULL);
    //    if (majorStatus != GSS_S_COMPLETE) { 
    //        err = minorStatus ? minorStatus : majorStatus; 
    //    }
    //    
    //    if (!err) {
    //        servicePrincipal = malloc (nameToken.length + 1);
    //        if (servicePrincipal == NULL) { err = ENOMEM; }
    //    }
    //    
    //    if (!err) {
    //        memcpy (servicePrincipal, nameToken.value, nameToken.length);
    //        servicePrincipal[nameToken.length] = '\0';
    //    }        

    //    if (nameToken.value) { gss_release_buffer (&minorStatus, &nameToken); }
    // }
    
//    if (!err) {
//        int authorizationErr = ServicePrincipalIsValidForService (servicePr// incipal);
//        
//        if (!authorizationErr) {

	  int authorizationErr = 0;
	  authorizationErr = ClientPrincipalIsAuthorizedForService (clientPrincipal);

//        }
        
//        printf ("'%s' is%s authorized for service '%s'\n", 
//                clientPrincipal, authorizationErr ? " NOT" : "", servicePrincipal);            
//        
	  *outAuthorized = !authorizationErr;
	  *outAuthorizationError = authorizationErr;
        }
    
    if (serviceName     ) { gss_release_name (&minorStatus, &serviceName); }
    if (clientName      ) { gss_release_name (&minorStatus, &clientName); }
    if (clientPrincipal ) { free (clientPrincipal); }
    if (servicePrincipal) { free (servicePrincipal); }

    return err; 
}


