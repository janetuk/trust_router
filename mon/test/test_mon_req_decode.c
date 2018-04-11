//
// Created by jlr on 4/9/18.
//

#include <talloc.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include <glib.h>

#include "../tr_mon_req.h"

/**
 * @return reconfigure command
 */
TR_MON_REQ *reconfigure()
{
  TR_MON_REQ *req = tr_mon_req_new(NULL, MON_CMD_RECONFIGURE);
  assert(req);
  return req;
}

/**
 * @return show command with no options
 */
TR_MON_REQ *show_plain()
{
  TR_MON_REQ *req = tr_mon_req_new(NULL, MON_CMD_SHOW);
  assert(req);
  return req;
}

/**
 * @param opts array of option types, terminated with OPT_TYPE_UNKNOWN
 * @return show command with the requested options, excluding the terminator
 */
TR_MON_REQ *show_options(const TR_MON_OPT_TYPE *opts)
{
  TR_MON_REQ *req = tr_mon_req_new(NULL, MON_CMD_SHOW);
  assert(req);

  while (*opts != OPT_TYPE_UNKNOWN) {
    assert(TR_MON_SUCCESS == tr_mon_req_add_option(req, *opts));
    opts++;
  }
  return req;
}

/**
 * @return show command with every option
 */
TR_MON_REQ *show_all_options()
{
  TR_MON_OPT_TYPE opts[] = {
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

char *read_file(const char *filename)
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

int equal(TR_MON_REQ *r1, TR_MON_REQ *r2)
{
  size_t ii;

  if (r1->command != r2->command)
    return 0;

  if (tr_mon_req_opt_count(r1) != tr_mon_req_opt_count(r2))
    return 0;

  for (ii=0; ii < tr_mon_req_opt_count(r1); ii++) {
    if (tr_mon_req_opt_index(r1, ii)->type != tr_mon_req_opt_index(r2, ii)->type)
      return 0;
  }

  return 1;
}

int run_test(const char *filename, TR_MON_REQ *(generator)())
{
  TR_MON_REQ *req = NULL;
  TR_MON_REQ *expected = NULL;
  char *req_json_str = NULL;

  expected = generator();
  assert(expected);

  req_json_str = read_file(filename);
  assert(req_json_str);

  req = tr_mon_req_decode(NULL, req_json_str);
  assert(req);
  assert(equal(req, expected));

  free(req_json_str);
  tr_mon_req_free(req);
  tr_mon_req_free(expected);

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