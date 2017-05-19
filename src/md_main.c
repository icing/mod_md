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
#include <apr_hash.h>
#include <apr_strings.h>

#include <jansson.h>

#include "md.h"
#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "md_util.h"
#include "mod_md.h"
#include "md_version.h"

static apr_getopt_option_t Options [] = {
    { "acme", 'a', 1, "the url of the ACME server directory"},
    { "dir", 'd', 1, "directory for file data"},
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
        fprintf(stderr, "%s\n", msg);
    }
    fprintf(stderr, "usage: a2md [options] cmd [cmd-args]\n");
    fprintf(stderr, "  with the following general options:\n");
    
    opt = NULL;
    for (i = 0; !opt || opt->optch; ++i) {
        opt = &Options[i];
        if (opt->optch) {
            fprintf(stderr, "  -%c | --%s    %s\t%s\n", 
                    opt->optch, opt->name, opt->has_arg? "arg" : "", opt->description);
            
        }
    }
    fprintf(stderr, "  using one of the following commands:\n");
    fprintf(stderr, "  \tnewreg contact...\n");
    fprintf(stderr, "  \t\tregister a new account with contact email(s)\n");
    fprintf(stderr, "  \tdelreg url\n");
    fprintf(stderr, "  \t\tdelete an account given its url\n");
    fprintf(stderr, "  \tlist\n");
    fprintf(stderr, "  \t\tlist all accounts and certificates\n");
}

static md_log_level_t active_level = MD_LOG_INFO;

static int log_is_level(void *baton, apr_pool_t *p, md_log_level_t level)
{
    return level <= active_level;
}

#define LOG_BUF_LEN 16*1024

void log_print(const char *file, int line, md_log_level_t level, 
               apr_status_t rv, void *baton, apr_pool_t *p, const char *fmt, va_list ap)
{
    if (log_is_level(baton, p, level)) {
        char buffer[LOG_BUF_LEN];
        char errbuff[32];
        
        apr_vsnprintf(buffer, LOG_BUF_LEN-1, fmt, ap);
        buffer[LOG_BUF_LEN-1] = '\0';
        
        if (rv) {
            fprintf(stderr, "[%s:%d %s][%d(%s)] %s\n", file, line, 
                    md_log_level_name(level), rv, 
                    apr_strerror(rv, errbuff, sizeof(errbuff)/sizeof(errbuff[0])), 
                    buffer);
        }
        else {
            fprintf(stderr, "[%s:%d %s][ok] %s\n", file, line, 
                    md_log_level_name(level), buffer);
        }
    }
}

static apr_status_t acme_newreg(md_acme *acme, apr_array_header_t *contacts) 
{
    md_http *http;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json *json;
    md_acme_acct *acct;
    
    rv = md_acme_setup(acme);
    if (rv != APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "contacting %s", acme->url);
        return rv;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, 
                  "acme setup state: %d, new_reg: %s", acme->state, acme->new_reg);
        
    rv = md_acme_register(&acct, acme, contacts);
    
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "registered: %s\n", acct->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "register new account");
    }
    return rv;
}

static apr_status_t acme_delreg(md_acme *acme, const char *acct_url) 
{
    md_http *http;
    md_acme_acct *acct;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json *json;
    
    rv = md_acme_setup(acme);
    if (rv != APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "contacting %s", acme->url);
        return rv;
    }
    
    acct = md_acme_acct_get(acme, acct_url);
    if (!acct) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "unknown account: %s", acct_url);
        return APR_ENOENT;
    }
    
    rv = md_acme_acct_del(acme, acct);
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "deleted: %s\n", acct->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "delete account");
    }
    return rv;
}

static int acct_print(void *baton, const void *key, apr_ssize_t klen, const void *value)
{
    apr_pool_t *pool = baton;
    const md_acme_acct *acct = value;
    md_json *json;
    
    json = md_json_create(pool);
    md_json_sets(acct->name, json, "name", NULL);
    md_json_sets(acct->url, json, "url", NULL);
    md_json_setsa(acct->contacts, json, "contact", NULL);
    fprintf (stdout, "%s\n", md_json_writep(json, MD_JSON_FMT_INDENT, pool));
    return 1;
}

static apr_status_t acme_list(md_acme *acme) 
{
    md_http *http;
    md_acme_acct *acct;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json *json;
    
    fprintf(stdout, "ACME server at %s\n", acme->url);
    fprintf(stdout, "accounts: %d\n", apr_hash_count(acme->accounts));
    apr_hash_do(acct_print, acme->pool, acme->accounts);
    
    return rv;
}

static int pool_abort(int rv)
{
    exit(1);
}

int main(int argc, const char **argv)
{
    apr_allocator_t *allocator;
    apr_status_t rv;
    apr_pool_t *pool;
    md_acme *acme;
    apr_getopt_t *os;
    int opt, do_run = 1, i;
    const char *optarg, *ca_url = NULL, **cpp, *cmd, *ca_path = NULL;
    
    md_log_set(log_is_level, log_print, NULL);
    
    apr_allocator_create(&allocator);
    rv = apr_pool_create_ex(&pool, NULL, pool_abort, allocator);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "error initializing pool\n");
        return 1;
    }
            
    apr_getopt_init(&os, pool, argc, argv);
    os->interleave = 1;
    while ((rv = apr_getopt_long(os, Options, &opt, &optarg)) == APR_SUCCESS) {
        switch (opt) {
            case 'a':
                ca_url = optarg;
                break;
            case 'd':
                ca_path = optarg;
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
    if (rv != APR_EOF) {
        usage(NULL);
        return 2;
    }
    if (!ca_url && !ca_path) {
        usage("either ACME url or a local directory needs to be specified");
        return 1;
    }
    
    if (do_run) {
        if (os->ind >= argc) {
            usage("cmd is missing");
            return 1;
        }
        
        md_acme_init(pool);
        rv = md_acme_create(&acme, pool, ca_url, ca_path);
        if (rv == APR_SUCCESS) {
        
            cmd = os->argv[os->ind];
            if (!strcmp("newreg", cmd)) {
                apr_array_header_t *contacts = apr_array_make(pool, 5, sizeof(const char *));
                for (i = os->ind + 1; i < argc; ++i) {
                    cpp = (const char **)apr_array_push(contacts);
                    *cpp = md_util_schemify(pool, os->argv[i], "mailto");
                }
                if (apr_is_empty_array(contacts)) {
                    usage("newreg needs at least one contact email as argument");
                }
                rv = acme_newreg(acme, contacts);
            }
            else if (!strcmp("delreg", cmd)) {
                for (i = os->ind + 1; i < argc; ++i) {
                    rv = acme_delreg(acme, os->argv[i]);
                    if (rv != APR_SUCCESS) {
                        break;
                    }
                }
            }
            else if (!strcmp("list", cmd)) {
                rv = acme_list(acme);
            }
            else {
                fprintf(stderr, "unknown command: %s\n", cmd);
                usage(NULL);
                return 1;
            }
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, pool, "creating acme for %s", ca_url);
        }
    }
    
    return (rv == APR_SUCCESS)? 0 : 1;
}
