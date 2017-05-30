/* Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
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

#include "md.h"
#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"
#include "mod_md.h"
#include "md_version.h"
#include "md_cmd.h"
#include "md_cmd_store.h"

/**************************************************************************************************/
/* command: store add */

static apr_status_t cmd_add(md_cmd_ctx *ctx, const md_cmd_t *cmd) 
{
    md_t *md, *nmd;
    const char *err, *optarg;
    apr_status_t rv;

    err = md_create(&md, ctx->p, md_cmd_gather_args(ctx, 0));
    if (err) {
        return APR_EINVAL;
    }

    md->ca_url = ctx->ca_url;
    md->ca_proto = "ACME";
    
    rv = md_store_save_md(ctx->store, md, 1);
    if (APR_SUCCESS == rv) {
        md_store_load_md(&nmd, ctx->store, md->name, ctx->p);
        md_cmd_print_md(ctx, nmd);
    }
    return rv;
}

static md_cmd_t AddCmd = {
    "add", MD_CTX_STORE, 
    NULL, cmd_add, MD_NoOptions, NULL,
    "add dns [dns2...]",
    "add a new managed domain 'dns' with all the additional domain names",
};

/**************************************************************************************************/
/* command: store remove */

static apr_status_t cmd_remove(md_cmd_ctx *ctx, const md_cmd_t *cmd) 
{
    const char *name;
    apr_status_t rv;
    int i;

    if (ctx->argc <= 0) {
        return usage(cmd, "needs at least one name");
    }
    
    for (i = 0; i < ctx->argc; ++i) {
        name = ctx->argv[i];
        rv = md_store_remove_md(ctx->store, name, md_cmd_ctx_has_option(ctx, "force"));
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "removing md %s", name);
            break;
        }
    }
    
    return rv;
}

static apr_status_t opts_remove(md_cmd_ctx *ctx, int option, const char *optarg)
{
    switch (option) {
        case 'f':
            md_cmd_ctx_set_option(ctx, "force", "1");
            break;
        default:
            return APR_EINVAL;
    }
    return APR_SUCCESS;
}

static apr_getopt_option_t RemoveOptions [] = {
    { "force",    'f', 0, "force removal, be silent about missing domains"},
    { NULL }
};

static md_cmd_t RemoveCmd = {
    "remove", MD_CTX_STORE, 
    opts_remove, cmd_remove, 
    RemoveOptions, NULL,
    "remove [options] name [name...]",
    "remove the managed domains <name> from the store",
};

/**************************************************************************************************/
/* command: store list */

static apr_status_t cmd_list(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_array_header_t *mdlist = apr_array_make(ctx->p, 5, sizeof(md_t *));
    apr_status_t rv;
    int i, j;
    
    rv = md_store_load(ctx->store, mdlist, ctx->p);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "loading store");
        return rv;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "mds loaded: %d", mdlist->nelts);
    for (i = 0; i < mdlist->nelts; ++i) {
        const md_t *md = APR_ARRAY_IDX(mdlist, i, const md_t*);
        md_cmd_print_md(ctx, md);
    }

    return APR_SUCCESS;
}

static md_cmd_t ListCmd = {
    "list", MD_CTX_STORE, 
    NULL, cmd_list, MD_NoOptions, NULL,
    "list",
    "list all managed domains in the store"
};

/**************************************************************************************************/
/* command: store update */

static apr_status_t cmd_update(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    const char *name;
    md_t *md;
    apr_status_t rv;
    int i, j, changed;
    
    if (ctx->argc <= 0) {
        return usage(cmd, "needs md name");
    }
    name = ctx->argv[0];
    
    rv = md_store_load_md(&md, ctx->store, name, ctx->p);
    if (APR_ENOENT == rv) {
        fprintf(stderr, "managed domain not found: %s\n", name);
        return rv;
    }
    else if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "loading store");
        return rv;
    }

    /* update what */
    changed = 0;
    
    if (ctx->argc > 1) {
        const char *aspect = ctx->argv[1];
        
        if (!strcmp("domains", aspect)) {
            md->domains = md_cmd_gather_args(ctx, 2);
            
            if (apr_is_empty_array(md->domains)) {
                fprintf(stderr, "update domains needs at least 1 domain name as parameter\n");
                return APR_EGENERAL;
            }
            changed = 1;
        }
        else {
            fprintf(stderr, "unknown update aspect: %s\n", aspect);
            return APR_ENOTIMPL;
        }
    }

    if (ctx->ca_url && (md->ca_url == NULL || strcmp(ctx->ca_url, md->ca_url))) {
        md->ca_url = ctx->ca_url;
        changed = 1;
    }
    
    if (changed) {
        rv = md_store_save_md(ctx->store, md, 0);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, ctx->p, "no changes necessary");
    }

    if (APR_SUCCESS == rv) {
        rv = md_store_load_md(&md, ctx->store, name, ctx->p);
        md_cmd_print_md(ctx, md);
    }
    return rv;
}

static md_cmd_t UpdateCmd = {
    "update", MD_CTX_STORE, 
    NULL, cmd_update, MD_NoOptions, NULL,
    "update <name>",
    "update the managed domain <name> in the store"
};

/**************************************************************************************************/
/* command: store */

static const md_cmd_t *StoreSubCmds[] = {
    &AddCmd,
    &RemoveCmd,
    &ListCmd,
    &UpdateCmd,
    NULL
};

md_cmd_t MD_StoreCmd = {
    "store", MD_CTX_STORE,  
    NULL, NULL, MD_NoOptions, StoreSubCmds,
    "store cmd [opts] [args]", 
    "manipulate the MD store", 
};

