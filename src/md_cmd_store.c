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
/* command: store list */

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
    apr_hash_t *mds = apr_hash_make(ctx->p);
    apr_status_t rv;
    int i, j;
    
    rv = md_store_load(ctx->store, mds, ctx->p);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "loading store");
        return rv;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "list do");
    apr_hash_do(list_add_md, mdlist, mds);
    qsort(mdlist->elts, mdlist->nelts, sizeof(md_t *), md_name_cmp);
    
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
    apr_array_header_t *mdlist = apr_array_make(ctx->p, 5, sizeof(md_t *));
    apr_hash_t *mds = apr_hash_make(ctx->p);
    apr_status_t rv;
    int i, j;
    
    rv = md_store_load(ctx->store, mds, ctx->p);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "loading store");
        return rv;
    }
    
    return APR_ENOTIMPL;
}

static md_cmd_t UpdateCmd = {
    "update", MD_CTX_STORE, 
    NULL, cmd_list, MD_NoOptions, NULL,
    "update",
    "update a managed domain in the store"
};

/**************************************************************************************************/
/* command: store */

static const md_cmd_t *StoreSubCmds[] = {
    &AddCmd,
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

