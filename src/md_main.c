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
#include <apr_getopt.h>
#include <apr_strings.h>

#include <jansson.h>

#include "md.h"
#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "mod_md.h"
#include "md_version.h"

static apr_getopt_option_t Options [] = {
    { "contact", 'c', 1, "contact url for the acme account"},
    { "quiet", 'q', 0, "produce less output"},
    { "verbose", 'v', 0, "produce more output" },
    { "version", 'V', 0, "print version" },
    { NULL, 0, 0, NULL }
};

static void usage(const char *msg) 
{
    apr_getopt_option_t *opt;
    int i;

    if (msg) {
        fprintf(stderr, "%s", msg);
    }
    fprintf(stderr, "usage: a2md ca-url\n");
    fprintf(stderr, "  with the following options:\n");
    
    opt = NULL;
    for (i = 0; !opt || opt->optch; ++i) {
        opt = &Options[i];
        if (opt->optch) {
            fprintf(stderr, "  -%c | --%s    %s\t%s\n", 
                    opt->optch, opt->name, opt->has_arg? "arg" : "", opt->description);
            
        }
    }
}

static md_log_level_t active_level = MD_LOG_INFO;

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
        
        if (status) {
            fprintf(stderr, "[%s:%d %s][err=%d] %s\n", file, line, 
                    md_log_level_name(level), status, buffer);
        }
        else {
            fprintf(stderr, "[%s:%d %s][ok] %s\n", file, line, 
                    md_log_level_name(level), buffer);
        }
    }
}

static apr_status_t run(md_acme *acme, apr_array_header_t *contacts) 
{
    md_http *http;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json *json;
    
    rv = md_acme_setup(acme);
    if (rv != APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "contacting %s", acme->url);
        return rv;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, 
                  "acme setup state: %d, new_reg: %s", acme->state, acme->new_reg);
        
    rv = md_acme_acct_new(acme, contacts, NULL, 4096);
    if (rv != APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "register new account");
        return rv;
    }
    
    rv = md_acme_acct_del(acme, acme->acct->url);
    if (rv != APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "delete account");
    }
    return rv;
}

int main(int argc, const char **argv)
{
    apr_allocator_t *allocator;
    apr_status_t status;
    apr_pool_t *pool;
    md_acme *acme;
    apr_getopt_t *os;
    int opt, do_run = 1;
    const char *optarg, *ca_url, **cpp;
    apr_array_header_t *contacts;
    
    md_log_set(log_is_level, log_print, NULL);
    
    apr_allocator_create(&allocator);
    status = apr_pool_create_ex(&pool, NULL, NULL, allocator);
    if (status != APR_SUCCESS) {
        fprintf(stderr, "error initializing pool\n");
        return 1;
    }
    contacts = apr_array_make(pool, 5, sizeof(const char *));
            
    apr_getopt_init(&os, pool, argc, argv);
    os->interleave = 1;
    while ((status = apr_getopt_long(os, Options, &opt, &optarg)) == APR_SUCCESS) {
        switch (opt) {
            case 'c':
                cpp = (const char **)apr_array_push(contacts);
                *cpp = optarg;
                break;
            case 'q':
                if (active_level > 0) {
                    --active_level;
                }
                break;
            case 'v':
                if (active_level < MD_LOG_TRACE8) {
                    ++active_level;
                }
                break;
            case 'V':
                fprintf(stdout, "version: %s\n", MOD_MD_VERSION);
                do_run = 0;
                break;
            default:
                usage(NULL);
                return 2;
        }
    }
    if (status != APR_EOF) {
        usage(NULL);
        return 2;
    }
    
    if (do_run) {
        if (os->ind + 1 != argc) {
            usage(NULL);
            return 2;
        }
        
        ca_url = os->argv[os->ind];
        
        md_acme_init(pool);
        status = md_acme_create(&acme, pool, ca_url);
        if (status == APR_SUCCESS) {
            status = run(acme, contacts);
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, status, pool, "creating acme for %s", ca_url);
        }
    }
    
    return (status == APR_SUCCESS)? 0 : 1;
}
