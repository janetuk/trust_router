/*
 * Copyright (c) 2016, JANET(UK)
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

/* Testing trp message encoding / decoding */

/* compiles with: gcc -o msgtst -I../include msgtst.c trp_msg.c $(pkg-config --cflags --libs glib-2.0) ../common/tr_debug.c  ../common/tr_name.c ../common/tr_msg.c -ltalloc -ljansson */

#include <stdio.h>
#include <talloc.h>

#include <trust_router/trp.h>
#include <tr_msg.h>
#include <tr_debug.h>

#define MAX_MSG_LEN 8192

int main(int argc, const char *argv[])
{
  TALLOC_CTX *main_ctx=talloc_new(NULL);
  FILE *f;
  char *buf;
  size_t buflen;
  TR_MSG *msg;
  
  if (argc != 2) {
    printf("Usage: %s <input file>\n\n", argv[0]);
    exit(-1);
  }

  buf=malloc(MAX_MSG_LEN);
  if (!buf) {
    printf("Allocation error.\n\n");
    exit(-1);
  }

  f=fopen(argv[1], "r");
  if (!f) {
    printf("Error opening %s for reading.\n\n", argv[1]);
    exit(-1);
  }

  printf("Reading from %s...\n", argv[1]);

  buflen=fread(buf, sizeof(char), MAX_MSG_LEN, f);
  if (buflen==0) {
    printf("File empty.\n\n");
    exit(0);
  }

  if (buflen>=MAX_MSG_LEN)
    printf("Warning: file may exceed maximum message length (%d bytes).\n", MAX_MSG_LEN);

  msg=tr_msg_decode(buf, buflen);

/*  if (rc==TRP_SUCCESS)
    trp_msg_print(msg);*/

  printf("\nEncoding...\n");

  printf("Result: \n%s\n\n", tr_msg_encode(msg));

  talloc_report_full(main_ctx, stdout);

  return 0;
}
