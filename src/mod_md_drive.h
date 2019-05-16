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

#ifndef mod_md_md_drive_h
#define mod_md_md_drive_h

struct md_mod_conf_t;
struct md_reg_t;

typedef struct md_drive_ctx md_drive_ctx;

/**
 * Start driving the certificate procotol for the domains mentioned in mc->drive_names.
 */
apr_status_t md_start_driving(struct md_mod_conf_t *mc, server_rec *s, apr_pool_t *p);


typedef struct md_drive_job_t md_drive_job_t;

struct md_drive_job_t {
    const char *name;      /* Name of the MD this job is about */     
    apr_time_t next_run;   /* Time this job wants to be processed next */
    int finished;          /* true iff the job finished successfully */
    apr_time_t valid_from; /* at which time the finished job results become valid */
    int notified;          /* true iff the user has been notified that results are valid now */
    int error_runs;        /* Number of errored runs of an unfinished job */
    int dirty;             /* transient flag if job needs saving */
};

apr_status_t md_drive_job_load(md_drive_job_t *job, struct md_reg_t *reg, apr_pool_t *p);



#endif /* mod_md_md_drive_h */
