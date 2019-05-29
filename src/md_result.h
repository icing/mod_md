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

#ifndef mod_md_md_result_h
#define mod_md_md_result_h

struct md_json_t;

typedef struct md_result_t md_result_t;

struct md_result_t {
    apr_pool_t *p;
    apr_status_t status;
    const char *problem;
    const char *detail;
    const char *activity;
    apr_time_t ready_at;
};

md_result_t *md_result_make(apr_pool_t *p, apr_status_t status);

void md_result_activity_set(md_result_t *result, const char *activity);
void md_result_activity_setn(md_result_t *result, const char *activity);

void md_result_set(md_result_t *result, apr_status_t status, const char *detail);
void md_result_problem_set(md_result_t *result, const char *problem, const char *detail);

void md_result_printf(md_result_t *result, apr_status_t status, const char *fmt, ...);

void md_result_delay_set(md_result_t *result, apr_time_t ready_at);

md_result_t*md_result_from_json(const struct md_json_t *json, apr_pool_t *p);
struct md_json_t *md_result_to_json(const md_result_t *result, apr_pool_t *p);

int md_result_cmp(const md_result_t *r1, const md_result_t *r2);

#endif /* mod_md_md_result_h */
