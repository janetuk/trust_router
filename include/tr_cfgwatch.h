#ifndef TR_CFGWATCH_H
#define TR_CFGWATCH_H

#include <talloc.h>
#include <time.h>
#include <sys/time.h>

#include <tr.h>


struct tr_fstat {
  char *name;
  struct timespec mtime;
};

struct tr_cfgwatch_data {
  struct timeval poll_interval; /* how often should we check for updates? */
  struct timeval settling_time; /* how long should we wait for changes to settle before updating? */
  char *config_dir; /* what directory are we watching? */
  struct tr_fstat *fstat_list; /* file names and mtimes */
  int n_files; /* number of files in fstat_list */
  int change_detected; /* have we detected a change? */
  struct timeval last_change_detected; /* when did we last note a changed mtime? */
  TALLOC_CTX *ctx; /* what context should own configuration talloc blocks? */
  TR_INSTANCE *tr; /* what trust router are we updating? */
};
typedef struct tr_cfgwatch_data TR_CFGWATCH;


/* prototypes */
TR_CFGWATCH *tr_cfgwatch_create(TALLOC_CTX *mem_ctx);
int tr_read_and_apply_config(TR_CFGWATCH *cfgwatch);
int tr_cfgwatch_event_init(struct event_base *base, TR_CFGWATCH *cfg_status, struct event **cfgwatch_ev);

#endif /* TR_CFGWATCH_H */
