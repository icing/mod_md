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

#ifndef md_status_h
#define md_status_h

struct md_json_t;
struct md_reg_t;

apr_status_t md_status_get_md_json(struct md_json_t **pjson, const md_t *md, 
                                   struct md_reg_t *reg, apr_pool_t *p);

apr_status_t md_status_get_json(struct md_json_t **pjson, apr_array_header_t *mds, 
                                struct md_reg_t *reg, apr_pool_t *p);

typedef struct md_status_job_t md_status_job_t;

struct md_status_job_t {
    const char *name;      /* Name of the MD this job is about */     
    apr_time_t next_run;   /* Time this job wants to be processed next */
    int finished;          /* true iff the job finished successfully */
    apr_time_t valid_from; /* at which time the finished job results become valid */
    int notified;          /* true iff the user has been notified that results are valid now */
    int error_runs;        /* Number of errored runs of an unfinished job */
    int last_status;       /* Status of last run */
    const char *last_message; /* Message from last run */
    int dirty;             /* transient flag if job needs saving */    
};

/**
 * Loads the raw JSON as persisted in the staging area.
 */
apr_status_t md_status_job_loadj(md_json_t **pjson, const char *name, 
                                 struct md_reg_t *reg, apr_pool_t *p);
/*
 * Load and convert the job stored in staging.
 */
apr_status_t md_status_job_load(md_status_job_t *job, struct md_reg_t *reg, apr_pool_t *p);

void md_status_job_to_json(md_json_t *json, const md_status_job_t *job);

apr_status_t md_status_job_save(md_status_job_t *job, struct md_reg_t *reg, apr_pool_t *p);


typedef struct md_status_stock_t md_status_stock_t;
struct md_status_stock_t {
    int ok_count;
    int renew_count;
    int errored_count;
    int ready_count;
};

void  md_status_take_stock(md_status_stock_t *stock, apr_array_header_t *mds, 
                           struct md_reg_t *reg, apr_pool_t *p);

#endif /* md_status_h */
