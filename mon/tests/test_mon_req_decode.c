//
// Created by jlr on 4/9/18.
//

#include <talloc.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include <glib.h>

#include <mon_internal.h>

/**
 * @return reconfigure command
 */
static MON_REQ *reconfigure()
{
  MON_REQ *req = mon_req_new(NULL, MON_CMD_RECONFIGURE);
  assert(req);
  return req;
}

/**
 * @return show command with no options
 */
static MON_REQ *show_plain()
{
  MON_REQ *req = mon_req_new(NULL, MON_CMD_SHOW);
  assert(req);
  return req;
}

/**
 * @param opts array of option types, terminated with OPT_TYPE_UNKNOWN
 * @return show command with the requested options, excluding the terminator
 */
static MON_REQ *show_options(const MON_OPT_TYPE *opts)
{
  MON_REQ *req = mon_req_new(NULL, MON_CMD_SHOW);
  assert(req);

  while (*opts != OPT_TYPE_UNKNOWN) {
    assert(MON_SUCCESS == mon_req_add_option(req, *opts));
    opts++;
  }
  return req;
}

/**
 * @return show command with every option
 */
static MON_REQ *show_all_options()
{
  MON_OPT_TYPE opts[] = {
      OPT_TYPE_SHOW_SERIAL,
      OPT_TYPE_SHOW_VERSION,
      OPT_TYPE_SHOW_UPTIME,
      OPT_TYPE_SHOW_TID_REQ_COUNT,
      OPT_TYPE_SHOW_TID_REQ_PENDING,
      OPT_TYPE_SHOW_ROUTES,
      OPT_TYPE_SHOW_COMMUNITIES,
      OPT_TYPE_UNKNOWN // terminator
  };

  return show_options(opts);
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

static int equal(MON_REQ *r1, MON_REQ *r2)
{
  size_t ii;

  if (r1->command != r2->command)
    return 0;

  if (mon_req_opt_count(r1) != mon_req_opt_count(r2))
    return 0;

  for (ii=0; ii < mon_req_opt_count(r1); ii++) {
    if (mon_req_opt_index(r1, ii)->type != mon_req_opt_index(r2, ii)->type)
      return 0;
  }

  return 1;
}

static int run_test(const char *filename, MON_REQ *(generator)())
{
  MON_REQ *req = NULL;
  MON_REQ *expected = NULL;
  char *req_json_str = NULL;

  expected = generator();
  assert(expected);

  req_json_str = read_file(filename);
  assert(req_json_str);

  req = mon_req_parse(NULL, req_json_str);
  assert(req);
  assert(equal(req, expected));

  free(req_json_str);
  mon_req_free(req);
  mon_req_free(expected);

  return 1;
}

int main(void)
{

  // Test reconfigure command
  assert(run_test("req_reconfigure.test", reconfigure));

  // Test show command with no options
  assert(run_test("req_show_no_options.test", show_plain));

  // Test show command with all the options
  assert(run_test("req_show_all_options.test", show_all_options));

  return 0;
}