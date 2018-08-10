//
// Created by jlr on 4/9/18.
//

#include <talloc.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include <glib.h>

#include <mon_internal.h>

#define JSON_DUMP_OPTS 0

static char *show_plain()
{
  MON_REQ *req = mon_req_new(NULL, MON_CMD_SHOW);
  json_t *req_json = mon_req_encode(req);
  char *result = json_dumps(req_json, JSON_DUMP_OPTS);
  assert(req);
  assert(req_json);
  assert(result);
  json_decref(req_json);
  mon_req_free(req);
  return result;
}

static char *show_options(const MON_OPT_TYPE *opts)
{
  MON_REQ *req = mon_req_new(NULL, MON_CMD_SHOW);
  json_t *req_json = NULL;
  char *result = NULL;

  assert(req);

  while (*opts != OPT_TYPE_UNKNOWN) {
    assert(MON_SUCCESS == mon_req_add_option(req, *opts));
    opts++;
  }

  req_json = mon_req_encode(req);
  assert(req_json);

  result = json_dumps(req_json, JSON_DUMP_OPTS);
  assert(result);

  json_decref(req_json);
  mon_req_free(req);
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
  MON_OPT_TYPE opts[10];
  char *expected = NULL;

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
  opts[0] = OPT_TYPE_SHOW_CONFIG_FILES;
  opts[1] = OPT_TYPE_SHOW_VERSION;
  opts[2] = OPT_TYPE_SHOW_UPTIME;
  opts[3] = OPT_TYPE_SHOW_TID_REQS_PROCESSED;
  opts[4] = OPT_TYPE_SHOW_TID_REQS_PENDING;
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