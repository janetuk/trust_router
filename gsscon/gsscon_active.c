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

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include <gsscon.h>

/* ---------------------------------------------------------------------------
 */

int gsscon_connect (const char *inHost, unsigned int inPort, const char *inServiceName, int *outFD, gss_ctx_id_t *outGSSContext)
{
  int err = 0;
  int fd = -1;
  OM_uint32 majorStatus;
  OM_uint32 minorStatus = 0, minorStatusToo = 0;
  struct addrinfo *ai=NULL;
  struct addrinfo *ai_head=NULL;
  struct addrinfo hints={.ai_family=AF_UNSPEC, .ai_socktype=SOCK_STREAM, .ai_protocol=IPPROTO_TCP};
  struct sockaddr_in saddr;
  char *port=NULL;
  gss_name_t serviceName = NULL;
  gss_name_t clientName = NULL;
  gss_cred_id_t clientCredentials = GSS_C_NO_CREDENTIAL;
  gss_ctx_id_t gssContext = GSS_C_NO_CONTEXT;
  OM_uint32 actualFlags = 0;
  char *inputTokenBuffer = NULL;
  size_t inputTokenBufferLength = 0;
  gss_buffer_desc inputToken;  /* buffer received from the server */
  gss_buffer_desc nameBuffer;
  gss_buffer_t inputTokenPtr = GSS_C_NO_BUFFER;
  char *name;

  if (!inServiceName) { err = EINVAL; }
  if (!outGSSContext) { err = EINVAL; }
    
  if (!err) {
    /* get a string for getaddrinfo */
    if (asprintf(&port, "%d", inPort)>0) { 
      err=getaddrinfo(inHost, port, &hints, &ai_head);
      free(port);
    } else
      err=1;
  }
    
  if (!err) {
    /* try all options returned until one works */
    for (ai=ai_head,fd=-1; (ai!=NULL) && (fd==-1); ai=ai->ai_next) {
      fd=socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      if (fd < 0) {
        fd=-1;
        continue;
      }

      fprintf(stderr, "gss_connect: Connecting to host '%s' on port %d\n", inHost, inPort);
      err=connect(fd, ai->ai_addr, ai->ai_addrlen);
      if (err!=0) {
        close(fd);
        fd=-1;
        continue;
      }
    }

    if (fd==-1)
      err=1;
  }
    
  if (!err) {
    *outFD = fd;
    fd = -1; /* takes ownership */
  } else {
    gsscon_print_error (err, "OpenConnection failed");
  }
    
  if (fd >= 0) { close (fd); }

  if (!err) {
    majorStatus = gss_acquire_cred (&minorStatus, clientName, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, 
                                    GSS_C_INITIATE, &clientCredentials, NULL, NULL); 
    if (majorStatus != GSS_S_COMPLETE) { 
      gsscon_print_gss_errors ("gss_acquire_cred", majorStatus, minorStatus);
      err = minorStatus ? minorStatus : majorStatus; 
    }
  }
    
  /*
   * Here is where the client picks the service principal it will
   * try to use to connect to the server.  In the case of the
   * gssClientSample, the service principal is passed in on the
   * command line, however, in a real world example, this would be
   * unacceptable from a user interface standpoint since the user
   * shouldn't need to know the server's service principal.
   * 
   * In traditional Kerberos setups, the service principal would be
   * constructed from the type of the service (eg: "imap"), the DNS
   * hostname of the server (eg: "mailserver.domain.com") and the
   * client's local realm (eg: "DOMAIN.COM") to form a full
   * principal string (eg: "imap/mailserver.domain.com@DOMAIN.COM").
   *
   * Now that many sites do not have DNS, this setup is becoming
   * less common.  However you decide to generate the service
   * principal, you need to adhere to the following constraint: The
   * service principal must be constructed by the client, typed in
   * by the user or administrator, or transmitted to the client in a
   * secure manner from a trusted third party -- such as through an
   * encrypted connection to a directory server.  You should not
   * have the server send the client the service principal name as
   * part of the authentication negotiation.
   *
   * The reason you can't let the server tell the client which
   * principal to use is that many machines at a site will have
   * their own service principal and keytab which identifies the
   * machine -- in a Windows Active Directory environment all
   * machines have a service principal and keytab.  Some of these
   * machines (such as a financial services server) will be more
   * trustworthy than others (such as a random machine on a
   * coworker's desk).  If the owner of one of these untrustworthy
   * machines can trick the client into using the untrustworthy
   * machine's principal instead of the financial services server's
   * principal, then he can trick the client into authenticating and
   * connecting to the untrustworthy machine.  The untrustworthy
   * machine can then harvest any confidential information the
   * client sends to it, such as credit card information or social
   * security numbers.
   *
   * If your protocol already involves sending the service principal
   * as part of your authentication negotiation, your client should
   * cache the name it gets after the first successful
   * authentication so that the problem above can only happen on the
   * first connection attempt -- similar to what ssh does with host
   * keys.
   */
    
  if (!err) {
    nameBuffer.length = asprintf(&name, "%s@%s", inServiceName, inHost);
    nameBuffer.value = name;

    majorStatus = gss_import_name (&minorStatus, &nameBuffer, (gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &serviceName); 
    if (majorStatus != GSS_S_COMPLETE) { 
      gsscon_print_gss_errors ("gss_import_name(inServiceName)", majorStatus, minorStatus);
      err = minorStatus ? minorStatus : majorStatus; 
    }
  }
    
  /* 
   * The main authentication loop:
   *
   * GSS is a multimechanism API.  Because the number of packet
   * exchanges required to authenticate can vary between mechanisms,
   * we need to loop calling gss_init_sec_context, passing the
   * "input tokens" received from the server and send the resulting
   * "output tokens" back until we get GSS_S_COMPLETE or an error.
   */

  majorStatus = GSS_S_CONTINUE_NEEDED;

  gss_OID_desc EAP_OID = { 9, "\x2B\x06\x01\x05\x05\x0F\x01\x01\x11" };
 
  while (!err && (majorStatus != GSS_S_COMPLETE)) {
    gss_buffer_desc outputToken = { 0, NULL }; /* buffer to send to the server */
    OM_uint32 requestedFlags = (GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | 
                                GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG);
        
    majorStatus = gss_init_sec_context (&minorStatus, 
                                        clientCredentials, 
                                       &gssContext, 
                                        serviceName, 
                                       &EAP_OID /* mech_type */,
                                        requestedFlags, 
                                        GSS_C_INDEFINITE, 
                                        GSS_C_NO_CHANNEL_BINDINGS, 
                                        inputTokenPtr,
                                        NULL /* actual_mech_type */, 
                                       &outputToken, 
                                       &actualFlags, 
                                        NULL /* time_rec */);
        
    /* Send the output token to the server (even on error) */
    if ((outputToken.length > 0) && (outputToken.value != NULL)) {
      err = gsscon_write_token (*outFD, outputToken.value, outputToken.length);
            
      /* free the output token */
      gss_release_buffer (&minorStatusToo, &outputToken);
    }
        
    if (!err) {
      if (majorStatus == GSS_S_CONTINUE_NEEDED) { 
        /* Protocol requires another packet exchange */
                
        /* Clean up old input buffer */
        if (inputTokenBuffer) {
          free (inputTokenBuffer);
          inputTokenBuffer = NULL;  /* don't double-free */
        }
                
        /* Read another input token from the server */
        err = gsscon_read_token (*outFD, &inputTokenBuffer, &inputTokenBufferLength);
                
        if (!err) {
          /* Set up input buffers for the next run through the loop */
          inputToken.value = inputTokenBuffer;
          inputToken.length = inputTokenBufferLength;
          inputTokenPtr = &inputToken;
        }
      } else if (majorStatus != GSS_S_COMPLETE) {
        gsscon_print_gss_errors ("gss_init_sec_context", majorStatus, minorStatus);
        err = minorStatus ? minorStatus : majorStatus; 
      }
    }
  }
    
  if (!err) { 
    *outGSSContext = gssContext;
    gssContext = NULL;
  } else {
    gsscon_print_error (err, "AuthenticateToServer failed"); 
  }

  if (inputTokenBuffer) { free (inputTokenBuffer); }
  if (serviceName     ) { gss_release_name (&minorStatus, &serviceName); }
  if (clientName      ) { gss_release_name (&minorStatus, &clientName); }
  if (ai_head         ) { freeaddrinfo(ai_head); }

  if (clientCredentials != GSS_C_NO_CREDENTIAL) { 
    gss_release_cred (&minorStatus, &clientCredentials); }
  if (gssContext != GSS_C_NO_CONTEXT) { 
    gss_delete_sec_context (&minorStatus, &gssContext, GSS_C_NO_BUFFER); }

  return err;
}

