//
// Created by jlr on 4/9/18.
//

#include <talloc.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>

#include <mon_internal.h>

#define JSON_DUMP_OPTS 0

static char *reconfigure(MON_RESP_CODE code, const char *message)
{
  MON_REQ *req = NULL;
  MON_RESP *resp = NULL;
  json_t *resp_json = NULL;
  char *result = NULL;

  req = mon_req_new(NULL, MON_CMD_RECONFIGURE);
  assert(req);

  resp = mon_resp_new(NULL, code, message, NULL);
  assert(resp);

  resp_json = mon_resp_encode(resp);
  assert(resp_json);

  result = json_dumps(resp_json, JSON_DUMP_OPTS);
  assert(result);

  json_decref(resp_json);
  mon_resp_free(resp);
  mon_req_free(req);
  return result;
}

static char *reconfigure_success()
{
  return reconfigure(MON_RESP_SUCCESS, "success");
}

static char *reconfigure_error()
{
  return reconfigure(MON_RESP_ERROR, "error");
}

static char *show_success()
{
  MON_REQ *req = NULL;
  MON_RESP *resp = NULL;
  json_t *resp_json = NULL;
  json_t *payload = NULL;
  char *result = NULL;

  req = mon_req_new(NULL, MON_CMD_SHOW);
  // Only need the command to be set in req, don't actually need the options
  assert(req);

  payload = json_object();
  assert(payload);
  assert(! json_object_set_new(payload,
                               mon_opt_type_to_string(OPT_TYPE_SHOW_VERSION),
                               json_string("1.2.3-4")));
  assert(! json_object_set_new(payload,
                               mon_opt_type_to_string(OPT_TYPE_SHOW_CONFIG_FILES),
                               json_integer(1234567890)));
  assert(! json_object_set_new(payload,
                               mon_opt_type_to_string(OPT_TYPE_SHOW_CONFIG_FILES),
                               json_integer(86400)));
  assert(! json_object_set_new(payload,
                               mon_opt_type_to_string(OPT_TYPE_SHOW_TID_REQ_PENDING),
                               json_integer(13)));
  assert(! json_object_set_new(payload,
                               mon_opt_type_to_string(OPT_TYPE_SHOW_TID_REQ_COUNT),
                               json_integer(1432)));

  resp = mon_resp_new(NULL, MON_RESP_SUCCESS, "success", payload);
  assert(resp);

  resp_json = mon_resp_encode(resp);
  assert(resp_json);

  result = json_dumps(resp_json, JSON_DUMP_OPTS);
  assert(result);

  json_decref(resp_json);
  mon_resp_free(resp);
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

int run_test(const char *filename, char *(generator)())
{
  char *s = NULL;
  char *expected = NULL;

  // Test reconfigure command
  s = generator();
  expected = read_file(filename);
  assert(expected);
  assert(strcmp(expected, s) == 0);
  free(s);
  free(expected);

  return 1;
}

int main(void)
{
  assert(run_test("resp_reconfigure_success.test", reconfigure_success));
  assert(run_test("resp_reconfigure_error.test", reconfigure_error));
  assert(run_test("resp_show_success.test", show_success));
  return 0;
}
