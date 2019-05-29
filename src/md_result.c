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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_date.h>
#include <apr_time.h>
#include <apr_strings.h>

#include "md.h"
#include "md_json.h"
#include "md_result.h"

md_result_t *md_result_make(apr_pool_t *p, apr_status_t status)
{
    md_result_t *result;
    
    result = apr_pcalloc(p, sizeof(*result));
    result->p = p;
    result->status = status;
    return result;
}

void md_result_activity_set(md_result_t *result, const char *activity)
{
    result->activity = activity? apr_pstrdup(result->p, activity) : NULL;
}

void md_result_activity_setn(md_result_t *result, const char *activity)
{
    result->activity = activity;
}

void md_result_set(md_result_t *result, apr_status_t status, const char *detail)
{
    result->status = status;
    result->problem = NULL;
    if (detail) {
        result->detail = apr_pstrdup(result->p, detail);
    }
    else if (result->activity) {
        result->detail = apr_psprintf(result->p, "While %s", result->activity);
    }
    else {
        result->detail = NULL;
    }
}

void md_result_problem_set(md_result_t *result, const char *problem, const char *detail)
{
    result->status = APR_EGENERAL;
    result->problem = apr_pstrdup(result->p, problem);
    result->detail = apr_pstrdup(result->p, detail);
}

void md_result_printf(md_result_t *result, apr_status_t status, const char *fmt, ...)
{
    va_list ap;

    result->status = status;
    va_start(ap, fmt);
    result->detail = apr_pvsprintf(result->p, fmt, ap);
    va_end(ap);
}

void md_result_delay_set(md_result_t *result, apr_time_t ready_at)
{
    result->ready_at = ready_at;
}

md_result_t*md_result_from_json(const struct md_json_t *json, apr_pool_t *p)
{
    md_result_t *result;
    const char *s;
    
    result = md_result_make(p, APR_SUCCESS);
    result->status = (int)md_json_getl(json, MD_KEY_STATUS, NULL);
    result->problem = md_json_dups(p, json, MD_KEY_PROBLEM, NULL);
    result->detail = md_json_dups(p, json, MD_KEY_DETAIL, NULL);
    result->activity = md_json_dups(p, json, MD_KEY_ACTIVITY, NULL);
    s = md_json_dups(p, json, MD_KEY_VALID_FROM, NULL);
    if (s && *s) result->ready_at = apr_date_parse_rfc(s);

    return result;
}

struct md_json_t *md_result_to_json(const md_result_t *result, apr_pool_t *p)
{
    md_json_t *json;
    char ts[APR_RFC822_DATE_LEN];
   
    json = md_json_create(p);
    md_json_setl(result->status, json, MD_KEY_STATUS, NULL);
    if (result->problem) md_json_sets(result->problem, json, MD_KEY_PROBLEM, NULL);
    if (result->detail) md_json_sets(result->detail, json, MD_KEY_DETAIL, NULL);
    if (result->activity) md_json_sets(result->activity, json, MD_KEY_ACTIVITY, NULL);
    if (result->ready_at > 0) {
        apr_rfc822_date(ts, result->ready_at);
        md_json_sets(ts, json, MD_KEY_VALID_FROM, NULL);
    }
    return json;
}

static int str_cmp(const char *s1, const char *s2)
{
    if (s1 == s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    return strcmp(s1, s2);
}

int md_result_cmp(const md_result_t *r1, const md_result_t *r2)
{
    int n;
    if (r1 == r2) return 0;
    if (!r1) return -1;
    if (!r2) return 1;
    if ((n = r1->status - r2->status)) return n;
    if ((n = str_cmp(r1->problem, r2->problem))) return n;
    if ((n = str_cmp(r1->detail, r2->detail))) return n;
    if ((n = str_cmp(r1->activity, r2->activity))) return n;
    return (int)(r1->ready_at - r2->ready_at);
}
