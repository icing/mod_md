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

/**************************************************************************************************/
/* command infrastructure */

typedef struct md_opts md_opts;
typedef struct md_cmd_ctx  md_cmd_ctx;
typedef struct md_cmd_t md_cmd_t;

typedef apr_status_t md_cmd_opt_fn(md_cmd_ctx *ctx, int option, const char *optarg);
typedef apr_status_t md_cmd_do_fn(md_cmd_ctx *ctx, const md_cmd_t *cmd);

struct md_cmd_ctx {
    apr_pool_t *p;
    const char *base_dir;
    const char *ca_url;
    md_store_t *store;
    apr_hash_t *mds;

    int do_usage;
    int do_version;
    
    md_acme *acme;
    const char *tos;
    
    md_json *json_out;
    
    int argc;
    const char *const *argv;
};

struct md_cmd_t {
    const char *name;
    int needs_store;
    int needs_acme;
    
    md_cmd_opt_fn *opt_fn;
    md_cmd_do_fn *do_fn;
    
    const apr_getopt_option_t *opts;
    const md_cmd_t **sub_cmds;
    
    const char *synopsis;
    const char *description;
};

static apr_getopt_option_t NoOptions [] = {
    { NULL, 0, 0, NULL }
};

static void usage(const md_cmd_t *cmd, const char *msg) 
{
    const apr_getopt_option_t *opt;
    int i;

    if (msg) {
        fprintf(stderr, "%s\n", msg);
    }
    fprintf(stderr, "usage: %s\n", cmd->synopsis);
    if (cmd->description) {
        fprintf(stderr, "\t%s\n", cmd->description);
    }
    if (cmd->opts[0].name) {
        fprintf(stderr, "  with the following options:\n");
    
        opt = NULL;
        for (i = 0; !opt || opt->optch; ++i) {
            opt = cmd->opts + i;
            if (opt->optch) {
                fprintf(stderr, "  -%c | --%s    %s\t%s\n", 
                        opt->optch, opt->name, opt->has_arg? "arg" : "", opt->description);
                
            }
        }
    }
    if (cmd->sub_cmds && cmd->sub_cmds[0]) {
        fprintf(stderr, "  using one of the following commands:\n");
        for (i = 0; cmd->sub_cmds[i]; ++i) {
            fprintf(stderr, "  \t%s\n", cmd->sub_cmds[i]->synopsis);
            fprintf(stderr, "  \t\t%s\n", cmd->sub_cmds[i]->description);
        }
    }
    
    exit(msg? 1 : 2);
}

static const md_cmd_t *find_cmd(const md_cmd_t **cmds, const char *name) 
{
    int i;
    if (cmds) {
        for (i = 0; cmds[i]; ++i) {
            if (!strcmp(name, cmds[i]->name)) {
                return cmds[i];
            }
        }
    }
    return NULL;
}

static apr_status_t cmd_process(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_getopt_t *os;
    const char *optarg;
    int opt;
    apr_status_t rv = APR_SUCCESS;

    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, 
                  "start processing cmd %s", cmd->name); 

    apr_getopt_init(&os, ctx->p, ctx->argc, ctx->argv);
    while ((rv = apr_getopt_long(os, cmd->opts, &opt, &optarg)) == APR_SUCCESS) {
        if (!cmd->opt_fn) {
            usage(cmd, NULL);
        }
        else if (APR_SUCCESS != (rv = cmd->opt_fn(ctx, opt, optarg))) {
            usage(cmd, NULL);
        }
    }
    if (rv != APR_EOF) {
        usage(cmd, NULL);
    }
    
    if (ctx->do_usage) {
        usage(cmd, NULL);
    }
    if (ctx->do_version) {
        fprintf(stdout, "version: %s\n", MOD_MD_VERSION);
        exit(0);
    }
    
    ctx->argv = os->argv + os->ind;
    ctx->argc -= os->ind;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "args remaining: %d", ctx->argc);
                   
    if (cmd->needs_store && !ctx->store) {
        if (!ctx->base_dir) {
            fprintf(stderr, "need store directory for command: %s\n", cmd->name);
            return APR_EINVAL;
        }
        if (APR_SUCCESS != (rv = md_store_fs_init(&ctx->store, ctx->p, ctx->base_dir))) {
            fprintf(stderr, "error %d creating store for: %s\n", rv, ctx->base_dir);
            return APR_EINVAL;
        }
        if (APR_SUCCESS != (rv = md_store_load(ctx->store, ctx->mds, ctx->p))) {
            fprintf(stderr, "error loading store from: %s\n", ctx->base_dir);
            return APR_EINVAL;
        }
    }
    if (cmd->needs_acme && !ctx->acme) {
        rv = md_acme_create(&ctx->acme, ctx->p, ctx->ca_url, ctx->base_dir);
        if (APR_SUCCESS != rv) {
            fprintf(stderr, "error creating acme instance %s (%s)\n", 
                    ctx->ca_url, ctx->base_dir);
            return rv;
        }
        rv = md_acme_setup(ctx->acme);
        if (rv != APR_SUCCESS) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "contacting %s", ctx->ca_url);
            return rv;
        }
    }
    
    if (cmd->sub_cmds && cmd->sub_cmds[0]) {
        const md_cmd_t *sub_cmd;
        
        if (!ctx->argc) {
            usage(cmd, "sub command is missing");
        }
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "sub command %s", ctx->argv[0]);
        
        sub_cmd = find_cmd(cmd->sub_cmds, ctx->argv[0]);
        if (sub_cmd) {
            return cmd_process(ctx, sub_cmd);
        }
        else if (!cmd->do_fn) {
            fprintf(stderr, "unknown cmd: %s\n", ctx->argv[0]);
            return APR_EINVAL;
        }
    }
    
    if (cmd->do_fn) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "%s->do_fn", cmd->name);
        return cmd->do_fn(ctx, cmd);
    }
    return APR_EINVAL;
}

/**************************************************************************************************/
/* logging setup */

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

/**************************************************************************************************/
/* utils */

static void print_md(md_cmd_ctx *ctx, const md_t *md)
{
    if (ctx->json_out) {
        md_json *json = md_to_json(md, ctx->p);
        md_json_addj(json, ctx->json_out, "output", NULL);
    }
    else {
        int i;
        fprintf(stdout, "md: %s [", md->name);
        for (i = 0; i < md->domains->nelts; ++i) {
            const char *domain = APR_ARRAY_IDX(md->domains, i, const char*);
            fprintf(stdout, "%s%s", (i? ", " : ""), domain);
        }
        fprintf(stdout, "]\n");
    }
}

static int pool_abort(int rv)
{
    exit(1);
}

/**************************************************************************************************/
/* command: acme newreg */

static apr_status_t cmd_acme_newreg(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    const char **cpp;
    md_acme_acct *acct;
    int i;
    
    apr_array_header_t *contacts = apr_array_make(ctx->p, 5, sizeof(const char *));
    for (i = 0; i < ctx->argc; ++i) {
        cpp = (const char **)apr_array_push(contacts);
        *cpp = md_util_schemify(ctx->p, ctx->argv[i], "mailto");
    }
    if (apr_is_empty_array(contacts)) {
        usage(cmd, "newreg needs at least one contact email as argument");
        return APR_EGENERAL;
    }

    rv = md_acme_register(&acct, ctx->acme, contacts, ctx->tos);
    
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "registered: %s\n", acct->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "register new account");
    }
    
    return rv;
}

static md_cmd_t AcmeNewregCmd = {
    "newreg", 0, 1, 
    NULL, cmd_acme_newreg, NoOptions, NULL,
    "newreg contact-uri [contact-uri...]",
    "register a new account at ACME server with give contact uri (email)",
};

/**************************************************************************************************/
/* command: acme agree */

static apr_status_t acct_agree_tos(md_acme *acme, const char *acct_url, const char *tos) 
{
    md_http *http;
    md_acme_acct *acct;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json *json;
    
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

static apr_status_t cmd_acme_agree(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    for (i = 0; i < ctx->argc; ++i) {
        rv = acct_agree_tos(ctx->acme, ctx->argv[i], ctx->tos);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

static md_cmd_t AcmeAgreeCmd = {
    "agree", 0, 1, 
    NULL, cmd_acme_agree, NoOptions, NULL,
    "agree account",
    "agree to ACME terms of service",
};

/**************************************************************************************************/
/* command: acme delreg */

static apr_status_t acme_delreg(md_acme *acme, const char *acct_url) 
{
    md_http *http;
    md_acme_acct *acct;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json *json;
    
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

static apr_status_t cmd_acme_delreg(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    for (i = 0; i < ctx->argc; ++i) {
        rv = acme_delreg(ctx->acme, ctx->argv[i]);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

static md_cmd_t AcmeDelregCmd = {
    "delreg", 0, 1, 
    NULL, cmd_acme_delreg, NoOptions, NULL,
    "delreg account",
    "delete an existing ACME account",
};

/**************************************************************************************************/
/* command: acme authz */

static apr_status_t acme_newauthz(md_acme_acct *acct, const char *domain) 
{
    md_acme *acme = acct->acme;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json *json;
    md_acme_authz *authz;
    
    rv = md_acme_authz_register(&authz, domain, acct); 
    
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "authz: %s %s\n", domain, authz->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "register new authz");
    }
    return rv;
}

static apr_status_t cmd_acme_authz(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    const char *s;
    md_acme_acct *acct;
    apr_status_t rv;
    int i;
    
    if (ctx->argc <= 0) {
        usage(cmd, NULL);
        return APR_EGENERAL;
    }
    s = ctx->argv[0];
    acct = md_acme_acct_get(ctx->acme, s);
    if (!acct) {
        fprintf(stderr, "unknown account: %s\n", s);
        return APR_EGENERAL;
    }
    
    for (i = 1; i < ctx->argc; ++i) {
        rv = acme_newauthz(acct, ctx->argv[i]);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

static md_cmd_t AcmeAuthzCmd = {
    "authz", 0, 1, 
    NULL, cmd_acme_authz, NoOptions, NULL,
    "authz account domain",
    "request a new authorization for an account and domain",
};

/**************************************************************************************************/
/* command: acme list */

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

static apr_status_t cmd_acme_list(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    md_http *http;
    md_acme_acct *acct;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json *json;
    
    fprintf(stdout, "ACME server at %s\n", ctx->acme->url);
    fprintf(stdout, "accounts: %d\n", apr_hash_count(ctx->acme->accounts));
    apr_hash_do(acct_print, ctx->p, ctx->acme->accounts);
    
    return rv;
}

static md_cmd_t AcmeListCmd = {
    "list", 0, 1, 
    NULL, cmd_acme_list, NoOptions, NULL,
    "list",
    "list all known ACME accounts",
};

/**************************************************************************************************/
/* command: acme */

static const md_cmd_t *AcmeSubCmds[] = {
    &AcmeNewregCmd,
    &AcmeDelregCmd,
    &AcmeAgreeCmd,
    &AcmeAuthzCmd,
    &AcmeListCmd,
    NULL
};

static md_cmd_t AcmeCmd = {
    "acme", 0, 1,  
    NULL, NULL, NoOptions, AcmeSubCmds,
    "acme cmd [opts] [args]", 
    "play with the ACME server", 
};

/**************************************************************************************************/
/* command: add */

static apr_status_t cmd_add(md_cmd_ctx *ctx, const md_cmd_t *cmd) 
{
    md_t *md, *nmd;
    const char *err, *optarg, **ps;
    apr_array_header_t *domains = apr_array_make(ctx->p, 5, sizeof(const char *));
    apr_status_t rv;
    int i;
    
    for (i = 0; i < ctx->argc; ++i) {
        ps = (const char **)apr_array_push(domains);
        *ps = ctx->argv[i];
    }
    
    err = md_create(&md, ctx->p, domains);
    if (err) {
        return APR_EINVAL;
    }

    md->ca_url = ctx->ca_url;
    md->ca_proto = "ACME";
    rv = md_store_save_md(ctx->store, md);
    if (APR_SUCCESS == rv) {
        md_store_load_md(&nmd, ctx->store, md->name, ctx->p);
        print_md(ctx, nmd);
    }
    return rv;
}

static md_cmd_t AddCmd = {
    "add", 1, 0, 
    NULL, cmd_add, NoOptions, NULL,
    "add dns [dns2...]",
    "add a new managed domain 'dns' with all the additional domain names",
};

/**************************************************************************************************/
/* command: list */

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

static apr_status_t cmd_list(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_array_header_t *mdlist = apr_array_make(ctx->p, 5, sizeof(md_t *));
    int i, j;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "list do");
    
    apr_hash_do(list_add_md, mdlist, ctx->mds);
    qsort(mdlist->elts, mdlist->nelts, sizeof(md_t *), md_name_cmp);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "mds loaded: %d", mdlist->nelts);
    for (i = 0; i < mdlist->nelts; ++i) {
        const md_t *md = APR_ARRAY_IDX(mdlist, i, const md_t*);
        print_md(ctx, md);
    }

    return APR_SUCCESS;
}

static md_cmd_t ListCmd = {
    "list", 1, 0, 
    NULL, cmd_list, NoOptions, NULL,
    "list",
    "list all managed domains in the store"
};

/**************************************************************************************************/
/* command: update */

static apr_status_t cmd_update(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_array_header_t *mdlist = apr_array_make(ctx->p, 5, sizeof(md_t *));
    int i, j;
    
    apr_hash_do(list_add_md, mdlist, ctx->mds);
    qsort(mdlist->elts, mdlist->nelts, sizeof(md_t *), md_name_cmp);
    
    for (i = 0; i < mdlist->nelts; ++i) {
        const md_t *md = APR_ARRAY_IDX(mdlist, i, const md_t*);
        print_md(ctx, md);
    }

    return APR_SUCCESS;
}

static md_cmd_t UpdateCmd = {
    "update", 1, 0, 
    NULL, cmd_list, NoOptions, NULL,
    "update",
    "update a managed domain in the store"
};

/**************************************************************************************************/
/* command: main() */

static apr_status_t main_opts(md_cmd_ctx *ctx, int option, const char *optarg)
{
    switch (option) {
        case 'a':
            ctx->ca_url = optarg;
            break;
        case 'd':
            ctx->base_dir = optarg;
            break;
        case 'h':
            ctx->do_usage = 1;
            break;
        case 'j':
            ctx->json_out = md_json_create(ctx->p);
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
            ctx->do_version = 1;
            break;
        case 't':
            ctx->tos = optarg;
            break;
        default:
            return APR_EINVAL;
    }
    return APR_SUCCESS;
}

static const md_cmd_t *MainSubCmds[] = {
    &AcmeCmd,
    &AddCmd,
    &ListCmd,
    &UpdateCmd,
    NULL
};

static apr_getopt_option_t MainOptions [] = {
    { "acme",    'a', 1, "the url of the ACME server directory"},
    { "dir",     'd', 1, "directory for file data"},
    { "help",    'h', 0, "print usage information"},
    { "json",    'j', 0, "produce json output"},
    { "quiet",   'q', 0, "produce less output"},
    { "terms",   't', 1, "you agree to the terms of services (url)" },
    { "verbose", 'v', 0, "produce more output" },
    { "version", 'V', 0, "print version" },
    { NULL,       0,  0, NULL }
};

static md_cmd_t MainCmd = {
    "a2md", 0, 0, main_opts, NULL,
    MainOptions, MainSubCmds,
    "a2md [options] cmd [cmd options] [args]", 
    "Show and manipulate Apache Manged Domains", 
};

int main(int argc, const char *const *argv)
{
    apr_allocator_t *allocator;
    apr_status_t rv;
    apr_pool_t *pool;
    int i;
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
    
    md_acme_init(ctx.p);
    
    ctx.mds = apr_hash_make(ctx.p);
    ctx.argc = argc;
    ctx.argv = argv;
    
    rv = cmd_process(&ctx, &MainCmd);
    
    if (ctx.json_out) {
        md_json_setl(rv, ctx.json_out, "status", NULL);
        fprintf(stdout, "%s\n", md_json_writep(ctx.json_out, MD_JSON_FMT_INDENT, ctx.p));
    }
    
    return (rv == APR_SUCCESS)? 0 : 1;
}
