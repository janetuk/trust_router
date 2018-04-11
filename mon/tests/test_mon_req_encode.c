//
// Created by jlr on 4/9/18.
//

#include <talloc.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include <glib.h>

#include "../tr_mon_req.h"

#define JSON_DUMP_OPTS 0

static char *reconfigure()
{
  TR_MON_REQ *req = tr_mon_req_new(NULL, MON_CMD_RECONFIGURE);
  json_t *req_json = tr_mon_req_encode(req);
  char *result = json_dumps(req_json, JSON_DUMP_OPTS);
  assert(req);
  assert(req_json);
  assert(result);
  json_decref(req_json);
  tr_mon_req_free(req);
  return result;
}

static char *show_plain()
{
  TR_MON_REQ *req = tr_mon_req_new(NULL, MON_CMD_SHOW);
  json_t *req_json = tr_mon_req_encode(req);
  char *result = json_dumps(req_json, JSON_DUMP_OPTS);
  assert(req);
  assert(req_json);
  assert(result);
  json_decref(req_json);
  tr_mon_req_free(req);
  return result;
}

static char *show_options(const TR_MON_OPT_TYPE *opts)
{
  TR_MON_REQ *req = tr_mon_req_new(NULL, MON_CMD_SHOW);
  json_t *req_json = NULL;
  char *result = NULL;

  assert(req);

  while (*opts != OPT_TYPE_UNKNOWN) {
    assert(TR_MON_SUCCESS == tr_mon_req_add_option(req, *opts));
    opts++;
  }

  req_json = tr_mon_req_encode(req);
  assert(req_json);

  result = json_dumps(req_json, JSON_DUMP_OPTS);
  assert(result);

  json_decref(req_json);
  tr_mon_req_free(req);
  return result;
}

static char *read_file(const char *filename)
{
  FILE *f = fopen(filename, "r");
  char *s = NULL;
  size_t nn = 0;
  ssize_t n = getline(&s, &nn, f);
  fclose(f);

  if( (n > 0) && (s[n-1] == '\n'))
    s[n-1] = 0;

  return s;
}
int main(void)
{
  char *s = NULL;
  TR_MON_OPT_TYPE opts[10];
  char *expected = NULL;

  // Test reconfigure command
  s = reconfigure();
  expected = read_file("req_reconfigure.test");
  assert(expected);
  assert(strcmp(expected, s) == 0);
  free(s);
  free(expected);

  // Test show without options
  s = show_plain();
  expected = read_file("req_show_no_options.test");
  assert(expected);
  assert(strcmp(expected, s) == 0);
  free(s);
  free(expected);

  // Test show with empty options (this mostly tests the test)
  opts[0] = OPT_TYPE_UNKNOWN;
  s = show_options(opts);
  expected = read_file("req_show_no_options.test");
  assert(expected);
  assert(strcmp(expected, s) == 0);
  free(s);
  free(expected);

  // Test show with many options
  opts[0] = OPT_TYPE_SHOW_SERIAL;
  opts[1] = OPT_TYPE_SHOW_VERSION;
  opts[2] = OPT_TYPE_SHOW_UPTIME;
  opts[3] = OPT_TYPE_SHOW_TID_REQ_COUNT;
  opts[4] = OPT_TYPE_SHOW_TID_REQ_PENDING;
  opts[5] = OPT_TYPE_SHOW_ROUTES;
  opts[6] = OPT_TYPE_SHOW_COMMUNITIES;
  opts[7] = OPT_TYPE_UNKNOWN;
  s = show_options(opts);
  expected = read_file("req_show_all_options.test");
  assert(expected);
  assert(strcmp(expected, s) == 0);
  free(s);
  free(expected);

  return 0;
}