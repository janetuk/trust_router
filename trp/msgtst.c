/* Testing trp message encoding / decoding */

/* compiles with: gcc -o msgtst -I../include -I../include/trust_router msgtst.c trp_msg.c $(pkg-config --cflags --libs glib-2.0) ../common/tr_debug.c  ../common/tr_name.c -ltalloc -ljansson */

#include <stdio.h>
#include <talloc.h>

#include <trp_internal.h>
#include <tr_debug.h>

#define MAX_MSG_LEN 8192

int main(int argc, const char *argv[])
{
  TALLOC_CTX *main_ctx=talloc_new(NULL);
  FILE *f;
  char *buf;
  size_t buflen;
  TRP_RC rc;
  TRP_MSG *msg;
  
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

  rc=trp_parse_msg(main_ctx, buf, buflen, &msg);
  printf("trp_parse_msg returned %d\n\n", rc);

  trp_msg_print(msg);

  talloc_report_full(main_ctx, stderr);

  talloc_free(msg);

  talloc_report_full(main_ctx, stderr);
  return 0;
}
