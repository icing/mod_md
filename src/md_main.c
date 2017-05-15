/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_buckets.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_protocol.h>

#include <jansson.h>

#include "md.h"
#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "mod_md.h"
#include "md_version.h"

static void usage(const char *msg) 
{
    if (msg) {
        fprintf(stderr, "%s", msg);
    }
    fprintf(stderr, "usage: a2md ca-url\n");
}

static md_log_level_t active_level = MD_LOG_NOTICE;

static int log_is_level(void *baton, apr_pool_t *p, md_log_level_t level)
{
    return level <= active_level;
}

#define LOG_BUF_LEN 1024

void log_print(const char *file, int line, md_log_level_t level, 
               apr_status_t status, void *baton, apr_pool_t *p, const char *fmt, va_list ap)
{
    if (log_is_level(baton, p, level)) {
        char buffer[LOG_BUF_LEN];
        
        apr_vsnprintf(buffer, LOG_BUF_LEN-1, fmt, ap);
        buffer[LOG_BUF_LEN-1] = '\0';
        
        fprintf(stderr, "[%s:%d %s][%d] %s\n", file, line, 
                md_log_level_name(level), status, buffer);
    }
}

static apr_status_t run(apr_pool_t *pool, int argc, char *argv[]) 
{
    md_http *http;
    apr_status_t rv;
    long req_id;
    md_acme *acme;
    const char *url, *data;
    md_json *json;
    
    if (argc > 0) {
        url = argv[0];
        --argc;
        --argc;
    }
    
    rv = md_acme_create(&acme, pool, url);
    if (rv != APR_SUCCESS) return rv;
    
    rv = md_acme_setup(acme);
    if (rv == APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, pool, 
                      "acme setup state: %d, new_reg: %s\n", acme->state, acme->new_reg);
        
        rv = md_acme_new_reg(acme, NULL, 4096); 
        if (rv == APR_SUCCESS) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, pool, "acme acct registered: %d\n", rv);
        }
    }

    return rv;
}

int main(int argc, char *argv[])
{
    apr_allocator_t *allocator;
    apr_status_t status;
    apr_pool_t *pool;
    
    if (argc <= 1) {
        usage(NULL);
        return 2;
    }
    
    md_log_set(log_is_level, log_print, NULL);
    active_level = MD_LOG_TRACE1;
    
    apr_allocator_create(&allocator);
    status = apr_pool_create_ex(&pool, NULL, NULL, allocator);
    if (status == APR_SUCCESS) {
        md_acme_init(pool);
        status = run(pool, argc-1, argv+1);
    }
    else {
        fprintf(stderr, "error initializing pool\n");
    }
    
    return (status == APR_SUCCESS)? 0 : 1;
}
