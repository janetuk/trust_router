/*
 * Copyright (c) 2012, 2015, JANET(UK)
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

#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <argp.h>
#include <event2/event.h>
#include <talloc.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <tr.h>
#include <tr_filter.h>
#include <tid_internal.h>
#include <tr_config.h>
#include <tr_comm.h>
#include <tr_idp.h>
#include <tr_rp.h>
#include <tr_debug.h>

/* Structure to hold TR instance and original request in one cookie */
typedef struct tr_resp_cookie {
  TR_INSTANCE *tr;
  TID_REQ *orig_req;
} TR_RESP_COOKIE;


static void tr_tidc_resp_handler (TIDC_INSTANCE *tidc, 
			TID_REQ *req,
			TID_RESP *resp, 
			void *resp_cookie) 
{
  tr_debug("tr_tidc_resp_handler: Response received (conn = %d)! Realm = %s, Community = %s.", ((TR_RESP_COOKIE *)resp_cookie)->orig_req->conn, resp->realm->buf, resp->comm->buf);
  req->resp_rcvd = 1;

  /* TBD -- handle concatentation of multiple responses to single req */
  tids_send_response(((TR_RESP_COOKIE *)resp_cookie)->tr->tids, 
		     ((TR_RESP_COOKIE *)resp_cookie)->orig_req, 
		     resp);
  
  return;
}

static int tr_tids_req_handler (TIDS_INSTANCE *tids,
		      TID_REQ *orig_req, 
		      TID_RESP *resp,
		      void *tr_in)
{
  TIDC_INSTANCE *tidc = NULL;
  TR_RESP_COOKIE resp_cookie;
  TR_AAA_SERVER *aaa_servers = NULL;
  TR_NAME *apc = NULL;
  TID_REQ *fwd_req = NULL;
  TR_COMM *cfg_comm = NULL;
  TR_COMM *cfg_apc = NULL;
  TR_INSTANCE *tr = (TR_INSTANCE *) tr_in;
  int oaction = TR_FILTER_ACTION_REJECT;
  int rc = 0;
  time_t expiration_interval;

  if ((!tids) || (!orig_req) || (!resp) ||  (!tr)) {
    tr_debug("tr_tids_req_handler: Bad parameters");
    return -1;
  }

  tr_debug("tr_tids_req_handler: Request received (conn = %d)! Realm = %s, Comm = %s", orig_req->conn, 
	 orig_req->realm->buf, orig_req->comm->buf);
  if (tids)
    tids->req_count++;

  /* Duplicate the request, so we can modify and forward it */
  if (NULL == (fwd_req = tid_dup_req(orig_req))) {
    tr_debug("tr_tids_req_handler: Unable to duplicate request.");
    return -1;
  }

  if (NULL == (cfg_comm = tr_comm_lookup(tids->cookie, orig_req->comm))) {
    tr_notice("tr_tids_req_hander: Request for unknown comm: %s.", orig_req->comm->buf);
    tids_send_err_response(tids, orig_req, "Unknown community");
    return -1;
  }

  /* Check that the rp_realm matches the filter for the GSS name that 
   * was received. */

  if ((!(tr)->rp_gss) || 
      (!(tr)->rp_gss->filter)) {
    tr_notice("tr_tids_req_handler: No GSS name for incoming request.");
    tids_send_err_response(tids, orig_req, "No GSS name for request");
    return -1;
  }

  if ((TR_FILTER_NO_MATCH == tr_filter_process_rp_permitted(orig_req->rp_realm, (tr)->rp_gss->filter, orig_req->cons, &fwd_req->cons, &oaction)) ||
      (TR_FILTER_ACTION_REJECT == oaction)) {
    tr_notice("tr_tids_req_handler: RP realm (%s) does not match RP Realm filter for GSS name", orig_req->rp_realm->buf);
    tids_send_err_response(tids, orig_req, "RP Realm filter error");
    return -1;
  }
  /* Check that the rp_realm is a member of the community in the request */
  if (NULL == (tr_find_comm_rp(cfg_comm, orig_req->rp_realm))) {
    tr_notice("tr_tids_req_handler: RP Realm (%s) not member of community (%s).", orig_req->rp_realm->buf, orig_req->comm->buf);
    tids_send_err_response(tids, orig_req, "RP COI membership error");
    return -1;
  }

  /* Map the comm in the request from a COI to an APC, if needed */
  if (TR_COMM_COI == cfg_comm->type) {
    tr_debug("tr_tids_req_handler: Community was a COI, switching.");
    /* TBD -- In theory there can be more than one?  How would that work? */
    if ((!cfg_comm->apcs) || (!cfg_comm->apcs->id)) {
      tr_notice("No valid APC for COI %s.", orig_req->comm->buf);
      tids_send_err_response(tids, orig_req, "No valid APC for community");
      return -1;
    }
    apc = tr_dup_name(cfg_comm->apcs->id);

    /* Check that the APC is configured */
    if (NULL == (cfg_apc = tr_comm_lookup(tids->cookie, apc))) {
      tr_notice("tr_tids_req_hander: Request for unknown comm: %s.", apc->buf);
      tids_send_err_response(tids, orig_req, "Unknown APC");
      return -1;
    }

    fwd_req->comm = apc;
    fwd_req->orig_coi = orig_req->comm;

    /* Check that rp_realm is a  member of this APC */
    if (NULL == (tr_find_comm_rp(cfg_apc, orig_req->rp_realm))) {
      tr_notice("tr_tids_req_hander: RP Realm (%s) not member of community (%s).", orig_req->rp_realm->buf, orig_req->comm->buf);
      tids_send_err_response(tids, orig_req, "RP APC membership error");
      return -1;
    }
  }

  /* Find the AAA server(s) for this request */
  if (NULL == (aaa_servers = tr_idp_aaa_server_lookup(((TR_INSTANCE *)tids->cookie)->active_cfg->idp_realms, 
						      orig_req->realm, 
						      orig_req->comm))) {
      tr_debug("tr_tids_req_handler: No AAA Servers for realm %s, defaulting.", orig_req->realm->buf);
      if (NULL == (aaa_servers = tr_default_server_lookup (((TR_INSTANCE *)tids->cookie)->active_cfg->default_servers,
							   orig_req->comm))) {
	tr_notice("tr_tids_req_handler: No default AAA servers, discarded.");
        tids_send_err_response(tids, orig_req, "No path to AAA Server(s) for realm");
        return -1;
      }
  } else {
    /* if we aren't defaulting, check idp coi and apc membership */
    if (NULL == (tr_find_comm_idp(cfg_comm, fwd_req->realm))) {
      tr_notice("tr_tids_req_handler: IDP Realm (%s) not member of community (%s).", orig_req->realm->buf, orig_req->comm->buf);
      tids_send_err_response(tids, orig_req, "IDP community membership error");
      return -1;
    }
    if ( cfg_apc && (NULL == (tr_find_comm_idp(cfg_apc, fwd_req->realm)))) {
      tr_notice("tr_tids_req_handler: IDP Realm (%s) not member of APC (%s).", orig_req->realm->buf, orig_req->comm->buf);
      tids_send_err_response(tids, orig_req, "IDP APC membership error");
      return -1;
    }
  }

  /* send a TID request to the AAA server(s), and get the answer(s) */
  /* TBD -- Handle multiple servers */

  if (cfg_apc)
    expiration_interval = cfg_apc->expiration_interval;
  else expiration_interval = cfg_comm->expiration_interval;
  if (fwd_req->expiration_interval)
    fwd_req->expiration_interval =  (expiration_interval < fwd_req->expiration_interval) ? expiration_interval : fwd_req->expiration_interval;
  else fwd_req->expiration_interval = expiration_interval;
  /* Create a TID client instance */
  if (NULL == (tidc = tidc_create())) {
    tr_crit("tr_tids_req_hander: Unable to allocate TIDC instance.");
    tids_send_err_response(tids, orig_req, "Memory allocation failure");
    return -1;
  }
  /* Use the DH parameters from the original request */
  /* TBD -- this needs to be fixed when we handle more than one req per conn */
  tidc->client_dh = orig_req->tidc_dh;

  /* Save information about this request for the response */
  resp_cookie.tr = tr;
  resp_cookie.orig_req = orig_req;

  /* Set-up TID connection */
  if (-1 == (fwd_req->conn = tidc_open_connection(tidc, 
						  aaa_servers->hostname->buf,
						  TID_PORT,
					      &(fwd_req->gssctx)))) {
    tr_notice("tr_tids_req_handler: Error in tidc_open_connection.");
    tids_send_err_response(tids, orig_req, "Can't open connection to next hop TIDS");
    return -1;
  };

  /* Send a TID request */
  if (0 > (rc = tidc_fwd_request(tidc, fwd_req, &tr_tidc_resp_handler, (void *)&resp_cookie))) {
    tr_notice("Error from tidc_fwd_request, rc = %d.", rc);
    tids_send_err_response(tids, orig_req, "Can't forward request to next hop TIDS");
    tid_req_free(orig_req);
    return -1;
  }
    
  tid_req_free(orig_req);
  return 0;
}

static int tr_tids_gss_handler(gss_name_t client_name, TR_NAME *gss_name,
			void *tr_in)
{
  TR_RP_CLIENT *rp;
  TR_INSTANCE *tr = (TR_INSTANCE *) tr_in;

  if ((!client_name) || (!gss_name) || (!tr)) {
    tr_debug("tr_tidc_gss_handler: Bad parameters.");
    return -1;
  }
  
  /* look up the RP client matching the GSS name */
  if ((NULL == (rp = tr_rp_client_lookup(tr->active_cfg->rp_clients, gss_name)))) {
    tr_debug("tr_tids_gss_handler: Unknown GSS name %s", gss_name->buf);
    return -1;
  }

  /* Store the rp client in the TR_INSTANCE structure for now... 
   * TBD -- fix me for new tasking model. */
  (tr)->rp_gss = rp;
  tr_debug("Client's GSS Name: %s", gss_name->buf);

  return 0;
}



/***** event loop management ****/

/* struct for hanging on to a socket listener event */
struct tr_socket_event {
  int sock_fd; /* the fd for the socket */
  struct event *ev; /* its event */
};

/* Allocate and set up the event base, return a pointer
 * to the new event_base or NULL on failure.
 * Does not currently enable thread-safe mode. */
static struct event_base *tr_event_loop_init(void)
{
  struct event_base *base=NULL;

  base=event_base_new();
  if (base==NULL) {
    tr_crit("Error initializing event loop.");
    return NULL;
  }
  return base;
}

/* run the loop, does not normally return */
static int tr_event_loop_run(struct event_base *base)
{
  return event_base_dispatch(base);
}

/* called when a connection to the TIDS port is received */
static void tr_tids_event_cb(int listener, short event, void *arg)
{
  TIDS_INSTANCE *tids = (TIDS_INSTANCE *)arg;

  if (0==(event & EV_READ))
    tr_debug("tr_tids_event_cb: unexpected event on TIDS socket (event=0x%X)", event);
  else 
    tids_accept(tids, listener);
}

/* Configure the tids instance and set up its event handler.
 * Returns 0 on success, nonzero on failure. Fills in
 * *tids_event (which should be allocated). */
static int tr_tids_event_init(struct event_base *base,
                              TR_INSTANCE *tr,
                              struct tr_socket_event *tids_ev)
{
  if (tids_ev == NULL) {
    tr_debug("tr_tids_event_init: Null tids_ev.");
    return 1;
  }

  /* get a tids listener */
  tids_ev->sock_fd=tids_get_listener(tr->tids,
                                      tr_tids_req_handler,
                                      tr_tids_gss_handler,
                                      tr->active_cfg->internal->hostname,
                                      tr->active_cfg->internal->tids_port,
                                      (void *)tr);
  if (tids_ev->sock_fd < 0) {
    tr_crit("Error opening TID server socket.");
    return 1;
  }

  /* and its event */
  tids_ev->ev=event_new(base,
                        tids_ev->sock_fd,
                        EV_READ|EV_PERSIST,
                        tr_tids_event_cb,
                        (void *)tr->tids);
  event_add(tids_ev->ev, NULL);

  return 0;
}


/***** config file watching *****/

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

/* Initialize a new tr_cfgwatch_data struct. Free this with talloc. */
static TR_CFGWATCH *tr_cfgwatch_create(TALLOC_CTX *mem_ctx)
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

/* must specify the ctx and tr in cfgwatch! */
static int tr_read_and_apply_config(TR_CFGWATCH *cfgwatch)
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
    tr_debug("tr_read_and_apply_config: Error decoding configuration information, rc=%d.", rc);
    retval=1; goto cleanup;
  }

  /* apply initial configuration */
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
  return retval;
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
static int tr_cfgwatch_event_init(struct event_base *base,
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


/***** command-line option handling / setup *****/

/* Strip trailing / from a path name.*/
static void remove_trailing_slash(char *s) {
  size_t n;

  n=strlen(s);
  if(s[n-1]=='/') {
    s[n-1]='\0';
  }
}

/* argp global parameters */
const char *argp_program_bug_address=PACKAGE_BUGREPORT; /* bug reporting address */

/* doc strings */
static const char doc[]=PACKAGE_NAME " - Moonshot Trust Router";
static const char arg_doc[]=""; /* string describing arguments, if any */

/* define the options here. Fields are:
 * { long-name, short-name, variable name, options, help description } */
static const struct argp_option cmdline_options[] = {
    { "config-dir", 'c', "DIR", 0, "Specify configuration file location (default is current directory)"},
    { NULL }
};

/* structure for communicating with option parser */
struct cmdline_args {
  char *config_dir;
};

/* parser for individual options - fills in a struct cmdline_args */
static error_t parse_option(int key, char *arg, struct argp_state *state)
{
  /* get a shorthand to the command line argument structure, part of state */
  struct cmdline_args *arguments=state->input;

  switch (key) {
  case 'c':
    if (arg == NULL) {
      /* somehow we got called without an argument */
      return ARGP_ERR_UNKNOWN;
    }
    arguments->config_dir=arg;
    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }

  return 0; /* success */
}

/* assemble the argp parser */
static struct argp argp = {cmdline_options, parse_option, arg_doc, doc};


int main (int argc, char *argv[])

{
  TALLOC_CTX *main_ctx=talloc_new(NULL);

  TR_INSTANCE *tr = NULL;
  struct cmdline_args opts;
  struct event_base *ev_base;
  struct tr_socket_event tids_ev;
  struct event *cfgwatch_ev;
  TR_CFGWATCH *cfgwatch; /* config file watcher status */

  /* Use standalone logging */
  tr_log_open();

  /***** parse command-line arguments *****/
  /* set defaults */
  opts.config_dir=".";

  /* parse the command line*/
  argp_parse(&argp, argc, argv, 0, 0, &opts);

  /* process options */
  remove_trailing_slash(opts.config_dir);

  /* Get a configuration status object */
  cfgwatch=tr_cfgwatch_create(main_ctx);
  if (cfgwatch == NULL) {
    tr_err("Unable to create configuration watcher object, exiting.");
    return 1;
  }
  
  /***** create a Trust Router instance *****/
  if (NULL == (tr = tr_create())) {
    tr_crit("Unable to create Trust Router instance, exiting.");
    return 1;
  }

  /***** process configuration *****/
  cfgwatch->config_dir=opts.config_dir;
  cfgwatch->ctx=main_ctx;
  cfgwatch->tr=tr;
  if (0 != tr_read_and_apply_config(cfgwatch)) {
    tr_crit("Error reading configuration, exiting.");
    return 1;
  }

  /***** initialize the trust path query server instance *****/
  if (0 == (tr->tids = tids_create ())) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    exit(1);
  }

  /***** Set up the event loop *****/
  ev_base=tr_event_loop_init(); /* Set up the event loop */

  /* install configuration file watching events */
  cfgwatch->poll_interval=(struct timeval) {1,0}; /* set poll interval in {sec, usec} */
  cfgwatch->settling_time=(struct timeval) {5,0}; /* delay for changes to settle before updating */
  
  /* already set config_dir, fstat_list and n_files earlier */
  if (0 != tr_cfgwatch_event_init(ev_base, cfgwatch, &cfgwatch_ev)) {
    tr_crit("Error initializing configuration file watcher.");
    exit(1);
  }

  /*tr_status_event_init();*/ /* install status reporting events */

  /* install TID server events */
  if (0 != tr_tids_event_init(ev_base, tr, &tids_ev)) {
    tr_crit("Error initializing Trust Path Query Server instance.");
    exit(1);
  }

  /*tr_trp_event_init();*/ /* install TRP handler events */

  fflush(stdout); fflush(stderr);
  tr_event_loop_run(ev_base); /* does not return until we are done */

  /* TODO: update the cleanup code */
  tids_destroy(tr->tids);
  tr_destroy(tr);

  talloc_free(main_ctx);
  exit(0);
}
