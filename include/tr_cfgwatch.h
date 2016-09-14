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

#ifndef TR_CFGWATCH_H
#define TR_CFGWATCH_H

#include <talloc.h>
#include <time.h>
#include <sys/time.h>

#include <tr_config.h>
#include <tr_event.h>
/* interval in seconds */
#define TR_CFGWATCH_DEFAULT_POLL 1
#define TR_CFGWATCH_DEFAULT_SETTLE 5
/* note: settling time is minimum - only checked on poll intervals */

struct tr_fstat {
  char *name;
  struct timespec mtime;
};

typedef struct tr_cfgwatch_data {
  struct timeval poll_interval; /* how often should we check for updates? */
  struct timeval settling_time; /* how long should we wait for changes to settle before updating? */
  char *config_dir; /* what directory are we watching? */
  struct tr_fstat *fstat_list; /* file names and mtimes */
  int n_files; /* number of files in fstat_list */
  int change_detected; /* have we detected a change? */
  struct timeval last_change_detected; /* when did we last note a changed mtime? */
  TR_CFG_MGR *cfg_mgr; /* what trust router config are we updating? */
  void (*update_cb)(TR_CFG *new_cfg, void *cookie); /* callback after config updated */
  void *update_cookie; /* data for the update_cb() */
} TR_CFGWATCH;


/* prototypes */
TR_CFGWATCH *tr_cfgwatch_create(TALLOC_CTX *mem_ctx);
int tr_read_and_apply_config(TR_CFGWATCH *cfgwatch);
int tr_cfgwatch_event_init(struct event_base *base, TR_CFGWATCH *cfg_status, struct event **cfgwatch_ev);

#endif /* TR_CFGWATCH_H */
