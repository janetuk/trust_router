/***** config file watching *****/

#include <sys/stat.h>
#include <talloc.h>

#include <tr_config.h>
#include <tr_debug.h>
#include <tr_event.h>
#include <tr_cfgwatch.h>

/* Initialize a new tr_cfgwatch_data struct. Free this with talloc. */
TR_CFGWATCH *tr_cfgwatch_create(TALLOC_CTX *mem_ctx)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  TR_CFGWATCH *new_cfg;
  
  new_cfg=talloc(tmp_ctx, TR_CFGWATCH);
  if (new_cfg == NULL) {
    tr_debug("tr_cfgwatch_create: Allocation failed.");
  } else {
    timerclear(&new_cfg->poll_interval);
    timerclear(&new_cfg->settling_time);
    new_cfg->config_dir=NULL;
    new_cfg->fstat_list=NULL;
    new_cfg->n_files=0;
    new_cfg->change_detected=0;
    timerclear(&new_cfg->last_change_detected);
    new_cfg->ctx=NULL;
    new_cfg->tr=NULL;
  }

  talloc_steal(mem_ctx, new_cfg);
  talloc_free(tmp_ctx);
  return new_cfg;
}

/* Obtain the file modification time as seconds since epoch. Returns 0 on success. */
static int tr_get_mtime(const char *path, struct timespec *ts)
{
  struct stat file_status;

  if (stat(path, &file_status) != 0) {
    return -1;
  } else {
    (*ts)=file_status.st_mtim;
  }
  return 0;
}

static char *tr_join_paths(TALLOC_CTX *mem_ctx, const char *p1, const char *p2)
{
  return talloc_asprintf(mem_ctx, "%s/%s", p1, p2); /* returns NULL on a failure */
}

static int tr_fstat_namecmp(const void *p1_arg, const void *p2_arg)
{
  struct tr_fstat *p1=(struct tr_fstat *) p1_arg;
  struct tr_fstat *p2=(struct tr_fstat *) p2_arg;

  return strcmp(p1->name, p2->name);
}

static int tr_fstat_mtimecmp(const void *p1_arg, const void *p2_arg)
{
  struct tr_fstat *p1=(struct tr_fstat *) p1_arg;
  struct tr_fstat *p2=(struct tr_fstat *) p2_arg;

  if (p1->mtime.tv_sec == p2->mtime.tv_sec)
    return (p1->mtime.tv_nsec) - (p2->mtime.tv_nsec);
  else
    return (p1->mtime.tv_sec) - (p2->mtime.tv_sec);
}

/* Get status of all files in cfg_files. Returns list, or NULL on error.
 * Files are sorted by filename. 
 * After success, caller must eventually free result with talloc_free. */
static struct tr_fstat *tr_fstat_get_all(TALLOC_CTX *mem_ctx,
                                         const char *config_path,
                                         struct dirent **cfg_files,
                                         int n_files)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_fstat *fstat_list=NULL;
  int ii=0;

  /* create a new fstat list (may be discarded) */
  fstat_list=talloc_array(tmp_ctx, struct tr_fstat, n_files);
  if (fstat_list==NULL) {
    tr_err("tr_fstat_get_all: Could not allocate fstat list.");
    goto cleanup;
  }

  for (ii=0; ii<n_files; ii++) {
    fstat_list[ii].name=talloc_strdup(fstat_list, cfg_files[ii]->d_name);
    if (0 != tr_get_mtime(tr_join_paths(tmp_ctx, config_path, fstat_list[ii].name),
                         &(fstat_list[ii].mtime))) {
      tr_warning("tr_fstat_get_all: Could not obtain mtime for file %s", fstat_list[ii].name);
    }
  }

  /* sort the list */
  qsort(fstat_list, n_files, sizeof(struct tr_fstat), tr_fstat_namecmp);

  /* put list in the caller's context and return it */
  talloc_steal(mem_ctx, fstat_list);
 cleanup:
  talloc_free(tmp_ctx);
  return fstat_list;
}

/* Checks whether any config files have appeared/disappeared/modified.
 * Returns 1 if so, 0 otherwise. */
static int tr_cfgwatch_update_needed(TR_CFGWATCH *cfg_status)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  struct tr_fstat *fstat_list=NULL;
  int n_files=0;
  int ii=0;
  struct dirent **cfg_files=NULL;
  int update_needed=0; /* return value */

  /* get the list, must free cfg_files later with tr_free_cfg_file_list */
  n_files = tr_find_config_files(cfg_status->config_dir, &cfg_files);
  if (n_files <= 0) {
    tr_warning("tr_cfgwatch_update: configuration files disappeared, skipping update.");
    goto cleanup;
  }

  /* create a new fstat list (will be discarded) */
  fstat_list=tr_fstat_get_all(tmp_ctx, cfg_status->config_dir, cfg_files, n_files);
  if (fstat_list==NULL) {
    tr_err("tr_cfgwatch_update: Error getting fstat list.");
    goto cleanup;
  }

  /* see if the number of files change, if so need to update */
  if (n_files != cfg_status->n_files) {
    tr_debug("tr_cfgwatch_update: Changed number of config files (was %d, now %d).",
             cfg_status->n_files,
             n_files);
    update_needed=1;
    talloc_free(cfg_status->fstat_list);
    cfg_status->n_files=n_files;
    cfg_status->fstat_list=fstat_list;
    talloc_steal(cfg_status->ctx, fstat_list);
    goto cleanup;
  }

  /* See if any files have a changed mtime. Both are sorted by name so this is easy. */
  for (ii=0; ii<n_files; ii++) {
    if ((0 != tr_fstat_mtimecmp(&fstat_list[ii], &cfg_status->fstat_list[ii]))
       || (0 != tr_fstat_namecmp(&fstat_list[ii], &cfg_status->fstat_list[ii]))){
      update_needed=1;
      talloc_free(cfg_status->fstat_list);
      cfg_status->n_files=n_files;
      cfg_status->fstat_list=fstat_list;
      talloc_steal(cfg_status->ctx, fstat_list);
      goto cleanup;
    }
  }

 cleanup:
  tr_free_config_file_list(n_files, &cfg_files);
  talloc_free(tmp_ctx);
  return update_needed;
}
/* must specify the ctx and tr in cfgwatch! */
int tr_read_and_apply_config(TR_CFGWATCH *cfgwatch)
{
  TALLOC_CTX *tmp_ctx=talloc_new(NULL);
  char *config_dir=cfgwatch->config_dir;
  int n_files = 0;
  struct dirent **cfg_files=NULL;
  TR_CFG_RC rc = TR_CFG_SUCCESS;	/* presume success */
  struct tr_fstat *new_fstat_list=NULL;
  int retval=0;

  /* find the configuration files -- n.b., tr_find_config_files()
   * allocates memory to cfg_files which we must later free */
  tr_debug("Reading configuration files from %s/", config_dir);
  n_files = tr_find_config_files(config_dir, &cfg_files);
  if (n_files <= 0) {
    tr_debug("tr_read_and_apply_config: No configuration files.");
    retval=1; goto cleanup;
  }

  /* Get the list of update times.
   * Do this before loading in case they change between obtaining their timestamp
   * and reading the file---this way they will immediately reload if this happens. */
  new_fstat_list=tr_fstat_get_all(tmp_ctx, config_dir, cfg_files, n_files);
  if (new_fstat_list==NULL) {
    tr_debug("tr_read_and_apply_config: Could not allocate config file status list.");
    retval=1; goto cleanup;
  }
  
  /* allocate a new configuration, dumping an old one if needed */
  if(cfgwatch->tr->new_cfg != NULL)
    tr_cfg_free(cfgwatch->tr->new_cfg);
  cfgwatch->tr->new_cfg=tr_cfg_new(tmp_ctx);
  if (cfgwatch->tr->new_cfg==NULL) {
    tr_debug("tr_read_and_apply_config: Error allocating new_cfg.");
    retval=1; goto cleanup;
  }
  /* now fill it in */
  if (TR_CFG_SUCCESS != (rc = tr_parse_config(cfgwatch->tr->new_cfg, config_dir, n_files, cfg_files))) {
    tr_debug("tr_read_and_apply_config: Error parsing configuration information, rc=%d.", rc);
    retval=1; goto cleanup;
  }

  /* apply initial configuration (frees active_cfg and resets new_cfg to NULL) */
  if (TR_CFG_SUCCESS != (rc = tr_apply_new_config(&cfgwatch->tr->active_cfg,
                                                 &cfgwatch->tr->new_cfg))) {
    tr_debug("tr_read_and_apply_config: Error applying configuration, rc = %d.", rc);
    retval=1; goto cleanup;
  }
  talloc_steal(cfgwatch->ctx, cfgwatch->tr->active_cfg); /* hand over ownership */

  /* give ownership of the new_fstat_list to caller's context */
  if (cfgwatch->fstat_list != NULL) {
    /* free the old one */
    talloc_free(cfgwatch->fstat_list);
  }
  cfgwatch->n_files=n_files;
  cfgwatch->fstat_list=new_fstat_list;
  talloc_steal(cfgwatch->ctx, new_fstat_list);
  new_fstat_list=NULL;

 cleanup:
  tr_free_config_file_list(n_files, &cfg_files);
  talloc_free(tmp_ctx);
  cfgwatch->tr->new_cfg=NULL; /* this has been freed, either explicitly or with tmp_ctx */
  return retval;
}


static void tr_cfgwatch_event_cb(int listener, short event, void *arg)
{
  TR_CFGWATCH *cfg_status=(TR_CFGWATCH *) arg;
  struct timeval now, diff;;

  if (tr_cfgwatch_update_needed(cfg_status)) {
    tr_notice("Configuration file change detected, waiting for changes to settle.");
    /*    if (!cfg_status->change_detected) {*/
      cfg_status->change_detected=1;

      if (0 != gettimeofday(&cfg_status->last_change_detected, NULL)) {
        tr_err("tr_cfgwatch_event_cb: gettimeofday() failed (1).");
        /*      }*/
    }
  }

  if (cfg_status->change_detected) {
    if (0 != gettimeofday(&now, NULL)) {
      tr_err("tr_cfgwatch_event_cb: gettimeofday() failed (2).");
    }
    timersub(&now, &cfg_status->last_change_detected, &diff);
    if (!timercmp(&diff, &cfg_status->settling_time, <)) {
      tr_notice("Configuration file change settled, updating configuration.");
      if (0 != tr_read_and_apply_config(cfg_status))
        tr_warning("Configuration file update failed. Using previous configuration.");
      else
        tr_notice("Configuration updated successfully.");
      cfg_status->change_detected=0;
    }
  }
}


/* Configure the cfgwatch instance and set up its event handler.
 * Returns 0 on success, nonzero on failure. Points
 * *cfgwatch_ev to the event struct. */
int tr_cfgwatch_event_init(struct event_base *base,
                           TR_CFGWATCH *cfg_status,
                           struct event **cfgwatch_ev)
{
  if (cfgwatch_ev == NULL) {
    tr_debug("tr_cfgwatch_event_init: Null cfgwatch_ev.");
    return 1;
  }

  /* zero out the change detection fields */
  cfg_status->change_detected=0;
  cfg_status->last_change_detected.tv_sec=0;
  cfg_status->last_change_detected.tv_usec=0;

  /* create the event and enable it */
  *cfgwatch_ev=event_new(base, -1, EV_TIMEOUT|EV_PERSIST, tr_cfgwatch_event_cb, (void *)cfg_status);
  event_add(*cfgwatch_ev, &(cfg_status->poll_interval));

  tr_info("tr_cfgwatch_event_init: Added configuration file watcher with %0d.%06d second poll interval.",
           cfg_status->poll_interval.tv_sec,
           cfg_status->poll_interval.tv_usec);
  return 0;
}

