/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include <assert.h>
#include <apr_optional.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include "mod_watchdog.h"

#include "md.h"
#include "md_curl.h"
#include "md_crypt.h"
#include "md_http.h"
#include "md_json.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_util.h"
#include "md_version.h"
#include "md_acme.h"
#include "md_acme_authz.h"

#include "mod_md.h"
#include "mod_md_private.h"
#include "mod_md_config.h"
#include "mod_md_status.h"
#include "mod_md_drive.h"


apr_status_t md_drive_job_update(md_drive_job_t *job, md_reg_t *reg, apr_pool_t *p)
{
    md_store_t *store = md_reg_store_get(reg);
    md_json_t *jprops;
    apr_status_t rv;
    
    rv = md_store_load_json(store, MD_SG_STAGING, job->md->name,
                            MD_FN_JOB, &jprops, p);
    if (APR_SUCCESS == rv) {
        job->restart_processed = md_json_getb(jprops, MD_KEY_PROCESSED, NULL);
        job->error_runs = (int)md_json_getl(jprops, MD_KEY_ERRORS, NULL);
    }
    return rv;
}

/**************************************************************************************************/
/* watchdog based impl. */

#define MD_WATCHDOG_NAME   "_md_"

static APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *wd_get_instance;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *wd_register_callback;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_set_callback_interval) *wd_set_interval;

struct md_drive_ctx {
    apr_pool_t *p;
    server_rec *s;
    md_mod_conf_t *mc;
    ap_watchdog_t *watchdog;
    
    apr_time_t next_change;
    apr_array_header_t *jobs;
};

static void assess_renewal(md_drive_ctx *dctx, md_drive_job_t *job, apr_pool_t *ptemp) 
{
    apr_time_t now = apr_time_now();
    if (now >= job->restart_at) {
        job->need_restart = 1;
        ap_log_error( APLOG_MARK, APLOG_TRACE1, 0, dctx->s, 
                     "md(%s): has been renewed, needs restart now", job->md->name);
    }
    else {
        job->next_check = job->restart_at;
        
        if (job->renewal_notified) {
            ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, dctx->s, 
                         "%s: renewed cert valid in %s", 
                         job->md->name, md_print_duration(ptemp, job->restart_at - now));
        }
        else {
            char ts[APR_RFC822_DATE_LEN];

            apr_rfc822_date(ts, job->restart_at);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, dctx->s, APLOGNO(10051) 
                         "%s: has been renewed successfully and should be activated at %s"
                         " (this requires a server restart latest in %s)", 
                         job->md->name, ts, md_print_duration(ptemp, job->restart_at - now));
            job->renewal_notified = 1;
        }
    }
}

static apr_status_t save_job_props(md_reg_t *reg, md_drive_job_t *job, apr_pool_t *p)
{
    md_store_t *store = md_reg_store_get(reg);
    md_json_t *jprops;
    apr_status_t rv;
    
    rv = md_store_load_json(store, MD_SG_STAGING, job->md->name, MD_FN_JOB, &jprops, p);
    if (APR_STATUS_IS_ENOENT(rv)) {
        jprops = md_json_create(p);
        rv = APR_SUCCESS;
    }
    if (APR_SUCCESS == rv) {
        md_json_setb(job->restart_processed, jprops, MD_KEY_PROCESSED, NULL);
        md_json_setl(job->error_runs, jprops, MD_KEY_ERRORS, NULL);
        rv = md_store_save_json(store, p, MD_SG_STAGING, job->md->name,
                                MD_FN_JOB, jprops, 0);
    }
    return rv;
}

static apr_status_t check_job(md_drive_ctx *dctx, md_drive_job_t *job, apr_pool_t *ptemp)
{
    apr_status_t rv = APR_SUCCESS;
    apr_time_t valid_from, delay;
    int error_runs;
    char ts[APR_RFC822_DATE_LEN];
    
    if (apr_time_now() < job->next_check) {
        /* Job needs to wait */
        return APR_EAGAIN;
    }
    
    job->next_check = 0;
    error_runs = job->error_runs;

    if (job->md->state == MD_S_MISSING) {
        job->stalled = 1;
    }
    
    if (job->stalled) {
        /* Missing information, this will not change until configuration
         * is changed and server restarted */
        rv = APR_INCOMPLETE;
        ++job->error_runs;
        goto out;
    }
    else if (job->renewed) {
        assess_renewal(dctx, job, ptemp);
    }
    else if (md_should_renew(job->md)) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10052) 
                     "md(%s): state=%d, driving", job->md->name, job->md->state);
        
        rv = md_reg_stage(dctx->mc->reg, job->md, NULL, dctx->mc->env, 0, &valid_from, ptemp);
        
        if (APR_SUCCESS == rv) {
            job->renewed = 1;
            job->restart_at = valid_from;
            assess_renewal(dctx, job, ptemp);
        }
    }
    else {
        /* Renew is not necessary yet, leave job->next_check as 0 since 
         * that keeps the default schedule of running twice a day. */
        apr_rfc822_date(ts, job->md->expires);
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10053) 
                     "md(%s): no need to renew yet, cert expires %s", job->md->name, ts);
    }
    
    if (APR_SUCCESS == rv) {
        job->error_runs = 0;
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_ERR, rv, dctx->s, APLOGNO(10056) 
                     "processing %s", job->md->name);
        ++job->error_runs;
        /* back off duration, depending on the errors we encounter in a row */
        delay = apr_time_from_sec(5 << (job->error_runs - 1));
        if (delay > apr_time_from_sec(60*60)) {
            delay = apr_time_from_sec(60*60);
        }
        job->next_check = apr_time_now() + delay;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, dctx->s, APLOGNO(10057) 
                     "%s: encountered error for the %d. time, next run in %s",
                     job->md->name, job->error_runs, md_print_duration(ptemp, delay));
    }
    
out:
    if (error_runs != job->error_runs) {
        apr_status_t rv2 = save_job_props(dctx->mc->reg, job, ptemp);
        ap_log_error(APLOG_MARK, APLOG_TRACE1, rv2, dctx->s, "%s: saving job props", job->md->name);
    }

    job->last_rv = rv;
    return rv;
}

static apr_status_t run_watchdog(int state, void *baton, apr_pool_t *ptemp)
{
    md_drive_ctx *dctx = baton;
    apr_status_t rv = APR_SUCCESS;
    md_drive_job_t *job;
    apr_time_t next_run, now;
    int restart = 0;
    int i;
    
    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10054)
                         "md watchdog start, auto drive %d mds", dctx->jobs->nelts);
            for (i = 0; i < dctx->jobs->nelts; ++i) {
                job = APR_ARRAY_IDX(dctx->jobs, i, md_drive_job_t *);
                md_drive_job_update(job, dctx->mc->reg, ptemp);
            }
            break;
        case AP_WATCHDOG_STATE_RUNNING:
        
            dctx->next_change = 0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10055)
                         "md watchdog run, auto drive %d mds", dctx->jobs->nelts);
                         
            /* normally, we'd like to run at least twice a day */
            next_run = apr_time_now() + apr_time_from_sec(MD_SECS_PER_DAY / 2);

            /* Check on all the jobs we have */
            for (i = 0; i < dctx->jobs->nelts; ++i) {
                job = APR_ARRAY_IDX(dctx->jobs, i, md_drive_job_t *);
                
                rv = check_job(dctx, job, ptemp);

                if (job->need_restart && !job->restart_processed) {
                    restart = 1;
                }
                if (job->next_check && job->next_check < next_run) {
                    next_run = job->next_check;
                }
            }

            now = apr_time_now();
            if (APLOGdebug(dctx->s)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10107)
                             "next run in %s", md_print_duration(ptemp, next_run - now));
            }
            wd_set_interval(dctx->watchdog, next_run - now, dctx, run_watchdog);
            break;
            
        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10058)
                         "md watchdog stopping");
            break;
    }

    if (restart) {
        const char *action, *names = "";
        int n;
        
        for (i = 0, n = 0; i < dctx->jobs->nelts; ++i) {
            job = APR_ARRAY_IDX(dctx->jobs, i, md_drive_job_t *);
            if (job->need_restart && !job->restart_processed) {
                names = apr_psprintf(ptemp, "%s%s%s", names, n? " " : "", job->md->name);
                ++n;
            }
        }

        if (n > 0) {
            int notified = 1;

            /* Run notify command for ready MDs (if configured) and persist that
             * we have done so. This process might be reaped after n requests or die
             * of another cause. The one taking over the watchdog need to notify again.
             */
            if (dctx->mc->notify_cmd) {
                const char * const *argv;
                const char *cmdline;
                int exit_code;
                
                cmdline = apr_psprintf(ptemp, "%s %s", dctx->mc->notify_cmd, names); 
                apr_tokenize_to_argv(cmdline, (char***)&argv, ptemp);
                if (APR_SUCCESS == (rv = md_util_exec(ptemp, argv[0], argv, &exit_code))) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, dctx->s, APLOGNO(10108) 
                                 "notify command '%s' returned %d", 
                                 dctx->mc->notify_cmd, exit_code);
                }
                else {
                    if (APR_EINCOMPLETE == rv && exit_code) {
                        rv = 0;
                    }
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, dctx->s, APLOGNO(10109) 
                                 "executing MDNotifyCmd %s returned %d", 
                                  dctx->mc->notify_cmd, exit_code);
                    notified = 0;
                } 
            }
            
            if (notified) {
                /* persist the jobs that were notified */
                for (i = 0, n = 0; i < dctx->jobs->nelts; ++i) {
                    job = APR_ARRAY_IDX(dctx->jobs, i, md_drive_job_t *);
                    if (job->need_restart && !job->restart_processed) {
                        job->restart_processed = 1;
                        save_job_props(dctx->mc->reg, job, ptemp);
                    }
                }
            }
            
            /* FIXME: the server needs to start gracefully to take the new certificate in.
             * This poses a variety of problems to solve satisfactory for everyone:
             * - I myself, have no implementation for Windows 
             * - on *NIX, child processes run with less privileges, preventing
             *   the signal based restart trigger to work
             * - admins want better control of timing windows for restarts, e.g.
             *   during less busy hours/days.
             */
            rv = APR_ENOTIMPL;/*md_server_graceful(ptemp, dctx->s);*/
            if (APR_ENOTIMPL == rv) {
                /* self-graceful restart not supported in this setup */
                action = " and changes will be activated on next (graceful) server restart.";
            }
            else {
                action = " and server has been asked to restart now.";
            }
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, dctx->s, APLOGNO(10059) 
                         "The Managed Domain%s %s %s been setup%s",
                         (n > 1)? "s" : "", names, (n > 1)? "have" : "has", action);
        }
    }
    
    return APR_SUCCESS;
}

apr_status_t md_start_driving(md_mod_conf_t *mc, server_rec *s, apr_pool_t *p)
{
    apr_allocator_t *allocator;
    md_drive_ctx *dctx;
    apr_pool_t *dctxp;
    apr_status_t rv;
    const char *name;
    md_t *md;
    md_drive_job_t *job;
    int i;
    
    /* We use mod_watchdog to run a single thread in one of the child processes
     * to monitor the MDs in mc->drive_names, using the const data in the list
     * mc->mds of our MD structures.
     *
     * The data in mc cannot be changed, as we may spawn copies in new child processes
     * of the original data at any time. The child which hosts the watchdog thread
     * may also die or be recycled, which causes a new watchdog thread to run
     * in another process with the original data.
     * 
     * Instead, we use our store to persist changes in group STAGING. This is
     * kept writable to child processes, but the data stored there is not live.
     * However, mod_watchdog makes sure that we only ever have a single thread in
     * our server (on this machine) that writes there. Other processes, e.g. informing
     * the user about progress, only read from there.
     *
     * All changes during driving an MD are stored as files in MG_SG_STAGING/<MD.name>.
     * All will have "md.json" and "job.json". There may be a range of other files used
     * by the protocol obtaining the certificate/keys.
     * 
     * 
     */
    wd_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    wd_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    wd_set_interval = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_set_callback_interval);
    
    if (!wd_get_instance || !wd_register_callback || !wd_set_interval) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(10061) "mod_watchdog is required");
        return !OK;
    }
    
    /* We want our own pool with own allocator to keep data across watchdog invocations.
     * Since we'll run in a single watchdog thread, using our own allocator will prevent 
     * any confusion in the parent pool. */
    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, 1);
    rv = apr_pool_create_ex(&dctxp, p, NULL, allocator);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10062) "md_drive_ctx: create pool");
        return rv;
    }
    apr_allocator_owner_set(allocator, dctxp);
    apr_pool_tag(dctxp, "md_drive_ctx");

    dctx = apr_pcalloc(dctxp, sizeof(*dctx));
    dctx->p = dctxp;
    dctx->s = s;
    dctx->mc = mc;
    
    dctx->jobs = apr_array_make(dctx->p, mc->drive_names->nelts, sizeof(md_drive_job_t *));
    for (i = 0; i < mc->drive_names->nelts; ++i) {
        name = APR_ARRAY_IDX(mc->drive_names, i, const char *);
        md = md_get_by_name(mc->mds, name);
        if (md) {
            if (md->state == MD_S_ERROR) {
                ap_log_error( APLOG_MARK, APLOG_WARNING, 0, dctx->s, APLOGNO() 
                             "md(%s): in error state, unable to drive forward. This "
                             "indicates an incomplete or inconsistent configuration. "
                             "Please check the log for warnings in this regard.", md->name);
            }
            else {
                if (md->state == MD_S_COMPLETE && !md->expires) {
                    ap_log_error( APLOG_MARK, APLOG_WARNING, 0, dctx->s, APLOGNO() 
                                 "md(%s): is complete but has no expiration date. This "
                                 "means it will never be renewed and should not happen.", md->name);
                }
                
                job = apr_pcalloc(dctx->p, sizeof(*job));
                job->md = md;
                APR_ARRAY_PUSH(dctx->jobs, md_drive_job_t*) = job;
                ap_log_error( APLOG_MARK, APLOG_TRACE1, 0, dctx->s,  
                             "md(%s): state=%d, created drive job", name, md->state);
                
                md_drive_job_update(job, mc->reg, dctx->p);
                if (job->error_runs) {
                    /* Server has just restarted. If we encounter an MD job with errors
                     * on a previous driving, we purge its STAGING area.
                     * This will reset the driving for the MD. It may run into the same
                     * error again, or in case of race/confusion/our error/CA error, it
                     * might allow the MD to succeed by a fresh start.
                     */
                    ap_log_error( APLOG_MARK, APLOG_INFO, 0, dctx->s, APLOGNO(10064) 
                                 "md(%s): previous drive job showed %d errors, purging STAGING "
                                 "area to reset.", name, job->error_runs);
                    md_store_purge(md_reg_store_get(dctx->mc->reg), p, MD_SG_STAGING, job->md->name);
                    md_store_purge(md_reg_store_get(dctx->mc->reg), p, MD_SG_CHALLENGES, job->md->name);
                    job->error_runs = 0;
                }
            }
        }
    }

    if (!dctx->jobs->nelts) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10065)
                     "no managed domain in state to drive, no watchdog needed, "
                     "will check again on next server (graceful) restart");
        apr_pool_destroy(dctx->p);
        return APR_SUCCESS;
    }
    
    if (APR_SUCCESS != (rv = wd_get_instance(&dctx->watchdog, MD_WATCHDOG_NAME, 0, 1, dctx->p))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(10066) 
                     "create md watchdog(%s)", MD_WATCHDOG_NAME);
        return rv;
    }
    rv = wd_register_callback(dctx->watchdog, 0, dctx, run_watchdog);
    ap_log_error(APLOG_MARK, rv? APLOG_CRIT : APLOG_DEBUG, rv, s, APLOGNO(10067) 
                 "register md watchdog(%s)", MD_WATCHDOG_NAME);
    return rv;
}
