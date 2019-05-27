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
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>
#include <apr_date.h>

#include "md_json.h"
#include "md.h"
#include "md_crypt.h"
#include "md_log.h"
#include "md_store.h"
#include "md_reg.h"
#include "md_util.h"
#include "md_status.h"


apr_status_t md_status_get_md_json(md_json_t **pjson, const md_t *md, 
                                   md_reg_t *reg, apr_pool_t *p)
{
    md_json_t *mdj, *jobj;
    int renew;
    apr_status_t rv = APR_SUCCESS;

    mdj = md_to_json(md, p);
    renew = md_should_renew(md);
    md_json_setb(renew, mdj, MD_KEY_RENEW, NULL);
    if (renew) {
        rv = md_status_job_loadj(&jobj, md->name, reg, p);
        if (APR_SUCCESS == rv) {
            md_json_setj(jobj, mdj, MD_KEY_RENEWAL, NULL);
        }
        else if (APR_STATUS_IS_ENOENT(rv)) rv = APR_SUCCESS;
        else goto leave;
        
    }
leave:
    *pjson = (APR_SUCCESS == rv)? mdj : NULL;
    return rv;
}

apr_status_t md_status_get_json(md_json_t **pjson, apr_array_header_t *mds, 
                                md_reg_t *reg, apr_pool_t *p) 
{
    md_json_t *json, *mdj;
    apr_status_t rv = APR_SUCCESS;
    const md_t *md;
    int i;
    
    json = md_json_create(p);
    md_json_sets(MOD_MD_VERSION, json, MD_KEY_VERSION, NULL);
    for (i = 0; i < mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mds, i, const md_t *);
        rv = md_status_get_md_json(&mdj, md, reg, p);
        if (APR_SUCCESS != rv) goto leave;
        md_json_addj(mdj, json, MD_KEY_MDS, NULL);
    }
leave:
    *pjson = (APR_SUCCESS == rv)? json : NULL;
    return rv;
}

/**************************************************************************************************/
/* drive job persistence */

static void md_status_job_from_json(md_status_job_t *job, const md_json_t *json, apr_pool_t *p)
{
    const char *s;
    /* not good, this is malloced from a temp pool */
    /*job->name = md_json_gets(json, MD_KEY_NAME, NULL);*/
    job->finished = md_json_getb(json, MD_KEY_FINISHED, NULL);
    s = md_json_dups(p, json, MD_KEY_NEXT_RUN, NULL);
    if (s && *s) job->next_run = apr_date_parse_rfc(s);
    s = md_json_dups(p, json, MD_KEY_VALID_FROM, NULL);
    if (s && *s) job->valid_from = apr_date_parse_rfc(s);
    job->notified = md_json_getb(json, MD_KEY_NOTIFIED, NULL);
    job->error_runs = (int)md_json_getl(json, MD_KEY_ERRORS, NULL);
    job->last_status = (int)md_json_getl(json, MD_KEY_LAST, MD_KEY_STATUS, NULL);
    job->last_message = md_json_dups(p, json, MD_KEY_LAST, MD_KEY_MESSAGE, NULL);
}

void md_status_job_to_json(md_json_t *json, const md_status_job_t *job)
{
    char ts[APR_RFC822_DATE_LEN];

    md_json_sets(job->name, json, MD_KEY_NAME, NULL);
    md_json_setb(job->finished, json, MD_KEY_FINISHED, NULL);
    if (job->next_run > 0) {
        apr_rfc822_date(ts, job->next_run);
        md_json_sets(ts, json, MD_KEY_NEXT_RUN, NULL);
    }
    if (job->valid_from > 0) {
        apr_rfc822_date(ts, job->valid_from);
        md_json_sets(ts, json, MD_KEY_VALID_FROM, NULL);
    }
    md_json_setb(job->notified, json, MD_KEY_NOTIFIED, NULL);
    md_json_setl(job->error_runs, json, MD_KEY_ERRORS, NULL);
    md_json_setl(job->last_status, json, MD_KEY_LAST, MD_KEY_STATUS, NULL);
    md_json_sets(job->last_message, json, MD_KEY_LAST, MD_KEY_MESSAGE, NULL);
}

apr_status_t md_status_job_loadj(md_json_t **pjson, const char *name, 
                                struct md_reg_t *reg, apr_pool_t *p)
{
    md_store_t *store = md_reg_store_get(reg);
    return md_store_load_json(store, MD_SG_STAGING, name, MD_FN_JOB, pjson, p);
}

apr_status_t md_status_job_load(md_status_job_t *job, md_reg_t *reg, apr_pool_t *p)
{
    md_store_t *store = md_reg_store_get(reg);
    md_json_t *jprops;
    apr_status_t rv;
    
    rv = md_store_load_json(store, MD_SG_STAGING, job->name, MD_FN_JOB, &jprops, p);
    if (APR_SUCCESS == rv) {
        md_status_job_from_json(job, jprops, p);
        job->dirty = 0;
    }
    return rv;
}

apr_status_t md_status_job_save(md_status_job_t *job, md_reg_t *reg, apr_pool_t *p)
{
    md_store_t *store = md_reg_store_get(reg);
    md_json_t *jprops;
    apr_status_t rv;
    
    jprops = md_json_create(p);
    md_status_job_to_json(jprops, job);
    rv = md_store_save_json(store, p, MD_SG_STAGING, job->name, MD_FN_JOB, jprops, 1);
    if (APR_SUCCESS == rv) job->dirty = 0;
    return rv;
}

void  md_status_take_stock(md_status_stock_t *stock, apr_array_header_t *mds, 
                           md_reg_t *reg, apr_pool_t *p)
{
    const md_t *md;
    md_status_job_t job;
    int i;

    memset(stock, 0, sizeof(*stock));
    for (i = 0; i < mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mds, i, const md_t *);
        switch (md->state) {
            case MD_S_COMPLETE: stock->ok_count++; /* fall through */
            case MD_S_INCOMPLETE:
                if (md_should_renew(md)) {
                    stock->renew_count++;
                    memset(&job, 0, sizeof(job));
                    job.name = md->name;
                    if (APR_SUCCESS == md_status_job_load(&job, reg, p)) {
                        if (job.error_runs > 0 || job.last_status != APR_SUCCESS) {
                            stock->errored_count++;
                        }
                        else if (job.finished) {
                            stock->ready_count++;
                        }
                    }
                }
                break;
            default: stock->errored_count++; break;
        }
    }
}


