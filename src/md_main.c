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
#include "md_acme_authz.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "md_store.h"
#include "md_util.h"
#include "mod_md.h"
#include "md_version.h"

#define TOS_DEFAULT     "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf"

static void usage(const char *msg); 

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

static apr_status_t acme_newreg(md_acme *acme, apr_array_header_t *contacts, 
                                const char *agreed_tos) 
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
    
    rv = md_acme_register(&acct, acme, contacts, agreed_tos);
    
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "registered: %s\n", acct->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "register new account");
    }
    return rv;
}

static apr_status_t acct_agree_tos(md_acme *acme, const char *acct_url, const char *tos) 
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
    
    if (!tos) {
        tos = acct->tos;
        if (!tos) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, acme->pool, 
                "terms-of-service not specified (--terms), using default %s", TOS_DEFAULT);
            tos = TOS_DEFAULT;
        }
    }
    rv = md_acme_acct_agree_tos(acct, tos);
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "agreed terms-of-service: %s\n", acct->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "agree to terms-of-service %s", tos);
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
    
    rv = md_acme_acct_del(acct);
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "deleted: %s\n", acct->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "delete account");
    }
    return rv;
}

static apr_status_t acme_newauthz(md_acme_acct *acct, const char *domain) 
{
    md_acme *acme = acct->acme;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json *json;
    md_acme_authz *authz;
    
    rv = md_acme_setup(acme);
    if (rv != APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "contacting %s", acme->url);
        return rv;
    }
    
    rv = md_acme_authz_register(&authz, domain, acct); 
    
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "authz: %s %s\n", domain, authz->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "register new authz");
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

typedef struct md_cmd_ctx {
    apr_pool_t *p;
    const char *ca_url;
    md_store_t *store;
    apr_hash_t *mds;

    md_acme *acme;
    const char *tos;
} md_cmd_ctx;

typedef apr_status_t md_cmd_fn(md_cmd_ctx *ctx, int argc, const char *const *argv);

static apr_status_t cmd_acme(md_cmd_ctx *ctx, int argc, const char *const *argv)
{
    apr_status_t rv;
    const char *subcmd, **cpp;
    int i;

    if (argc < 2) {
        fprintf(stderr, "acme: missing sub command\n");
        return APR_EGENERAL;
    }
    
    subcmd = argv[1];
    
    if (!strcmp("newreg", subcmd)) {
        apr_array_header_t *contacts = apr_array_make(ctx->p, 5, sizeof(const char *));
        for (i = 2; i < argc; ++i) {
            cpp = (const char **)apr_array_push(contacts);
            *cpp = md_util_schemify(ctx->p, argv[i], "mailto");
        }
        if (apr_is_empty_array(contacts)) {
            usage("newreg needs at least one contact email as argument");
            return APR_EGENERAL;
        }
        rv = acme_newreg(ctx->acme, contacts, ctx->tos);
    }
    else if (!strcmp("delreg", subcmd)) {
        for (i = 2; i < argc; ++i) {
            rv = acme_delreg(ctx->acme, argv[i]);
            if (rv != APR_SUCCESS) {
                break;
            }
        }
    }
    else if (!strcmp("agree", subcmd)) {
        for (i = 2; i < argc; ++i) {
            rv = acct_agree_tos(ctx->acme, argv[i], ctx->tos);
            if (rv != APR_SUCCESS) {
                break;
            }
        }
    }
    else if (!strcmp("authz", subcmd)) {
        const char *s;
        md_acme_acct *acct;
        
        if (2 >= argc) {
            usage(NULL);
            return APR_EGENERAL;
        }
        s = argv[2];
        acct = md_acme_acct_get(ctx->acme, s);
        if (!acct) {
            fprintf(stderr, "unknown account: %s\n", s);
            return APR_EGENERAL;
        }
        
        for (i = 3; i < argc; ++i) {
            rv = acme_newauthz(acct, argv[i]);
            if (rv != APR_SUCCESS) {
                break;
            }
        }
    }
    else if (!strcmp("list", subcmd)) {
        rv = acme_list(ctx->acme);
    }
    else {
        fprintf(stderr, "acme: unknown sub command: %s\n", subcmd);
        return APR_EGENERAL;
    }
    return rv;
}

static apr_status_t cmd_add(md_cmd_ctx *ctx, int argc, const char *const *argv) 
{
    md_t *md;
    const char *err;
    apr_status_t rv;
    
    err = md_create(&md, ctx->p, argc - 1, (char *const*)argv+1);
    if (err) {
        return APR_EINVAL;
    }

    md->ca_url = ctx->ca_url;
    md->ca_proto = "ACME";
    rv = md_store_save_md(ctx->store, md);
    fprintf(stderr, "saved md: %s\n", md->name);
    return rv;
}

static int list_add_md(void *baton, const void *key, apr_ssize_t klen, const void *val)
{
    apr_array_header_t *mdlist = baton;
    md_t **pmd;
    
    pmd = (md_t **)apr_array_push(mdlist);
    *pmd = (md_t*)val;
    return 1;
}

static int md_name_cmp(const void *v1, const void *v2)
{
    return strcmp(((const md_t*)v1)->name, ((const md_t*)v2)->name);
}

static apr_status_t cmd_list(md_cmd_ctx *ctx, int argc, const char *const *argv)
{
    apr_status_t rv;
    apr_array_header_t *mdlist = apr_array_make(ctx->p, 5, sizeof(md_t *));
    int i, j;
    
    apr_hash_do(list_add_md, mdlist, ctx->mds);
    qsort(mdlist->elts, mdlist->nelts, sizeof(md_t *), md_name_cmp);
    
    for (i = 0; i < mdlist->nelts; ++i) {
        const md_t *md = APR_ARRAY_IDX(mdlist, i, const md_t*);
        fprintf(stdout, "md: %s [", md->name);
        for (j = 0; j < md->domains->nelts; ++j) {
            const char *domain = APR_ARRAY_IDX(md->domains, j, const char*);
            fprintf(stdout, "%s%s", (j? ", " : ""), domain);
        }
        fprintf(stdout, "]\n");
    }
    return rv;
}

typedef struct md_cmd_t {
    const char *name;
    int needs_store;
    int needs_acme;
    md_cmd_fn *fn;
    const char *synopsis;
    const char *description;
} md_cmd_t;

static const md_cmd_t cmds[] = {
    { "acme", 0, 1, cmd_acme, "acme subcmd [options]", 
        "perform one of the acme commands: newreg, delreg, agree, list, authz" },
    { "add",  1, 0, cmd_add, "add domain [domain...]", 
        "add a managed domain to the store" },
    { "list", 1, 0, cmd_list, "list", 
        "list all managed domains in the store" }
};

static const md_cmd_t *find_cmd(const char *name) 
{
    int i;
    for (i = 0; i < sizeof(cmds)/sizeof(cmds[0]); ++i) {
        if (!strcmp(name, cmds[i].name)) {
            return &cmds[i];
        }
    }
    return NULL;
}

static apr_getopt_option_t Options [] = {
    { "acme", 'a', 1, "the url of the ACME server directory"},
    { "dir", 'd', 1, "directory for file data"},
    { "help", 'h', 0, "print usage information"},
    { "quiet", 'q', 0, "produce less output"},
    { "terms", 't', 1, "you agree to the terms of services (url)" },
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
    for (i = 0; i < sizeof(cmds)/sizeof(cmds[0]); ++i) {
        fprintf(stderr, "  \t%s\n", cmds[i].synopsis);
        fprintf(stderr, "  \t\t%s\n", cmds[i].description);
    }
    
    exit(msg? 1 : 2);
}

int main(int argc, const char *const *argv)
{
    apr_allocator_t *allocator;
    apr_status_t rv;
    apr_pool_t *pool;
    apr_getopt_t *os;
    int opt, do_version = 0, do_usage = 0, i;
    const char *optarg, *base_dir = NULL;
    apr_hash_t *mds;
    md_cmd_ctx ctx;
    const md_cmd_t *cmd;
    
    memset(&ctx, 0, sizeof(ctx));
    md_log_set(log_is_level, log_print, NULL);
    
    apr_allocator_create(&allocator);
    rv = apr_pool_create_ex(&ctx.p, NULL, pool_abort, allocator);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "error initializing pool\n");
        return 1;
    }
            
    apr_getopt_init(&os, ctx.p, argc, argv);
    os->interleave = 1;
    while ((rv = apr_getopt_long(os, Options, &opt, &optarg)) == APR_SUCCESS) {
        switch (opt) {
            case 'a':
                ctx.ca_url = optarg;
                break;
            case 'd':
                base_dir = optarg;
                break;
            case 'h':
                do_usage = 1;
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
                do_version = 1;
                break;
            case 't':
                ctx.tos = optarg;
                break;
            default:
                usage(NULL);
        }
    }
    if (rv != APR_EOF) {
        usage(NULL);
    }
    
    md_acme_init(ctx.p);
    
    if (do_usage) {
        usage(NULL);
    }
    if (do_version) {
        fprintf(stdout, "version: %s\n", MOD_MD_VERSION);
        return 0;
    }
    
    if (os->ind >= argc) {
        usage("cmd is missing");
    }

    i = os->ind;
    argv = os->argv + i;
    argc -= i;
    
    cmd = find_cmd(argv[0]);
    if (!cmd) {
        fprintf(stderr, "unknown cmd: %s\n", argv[0]);
        return 1;
    }
    
    ctx.mds = apr_hash_make(ctx.p);
    if (cmd->needs_store) {
        if (!base_dir) {
            fprintf(stderr, "need store directory for command: %s\n", cmd->name);
            return 1;
        }
        if (APR_SUCCESS != (rv = md_store_fs_init(&ctx.store, ctx.p, base_dir))) {
            fprintf(stderr, "error %d creating store for: %s\n", rv, base_dir);
            return 1;
        }
        if (APR_SUCCESS != (rv = md_store_load(ctx.store, ctx.mds))) {
            fprintf(stderr, "error loading store from: %s\n", base_dir);
            return 1;
        }
    }
    if (cmd->needs_acme) {
        rv = md_acme_create(&ctx.acme, ctx.p, ctx.ca_url, base_dir);
        if (APR_SUCCESS != rv) {
            fprintf(stderr, "error creating acme instance %s (%s)\n", ctx.ca_url, base_dir);
            return 1;
        }
    }
    
    rv = cmd->fn(&ctx, argc, argv);
    
    return (rv == APR_SUCCESS)? 0 : 1;
}
