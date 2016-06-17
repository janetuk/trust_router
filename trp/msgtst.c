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
