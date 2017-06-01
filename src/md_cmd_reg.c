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
#include "md_cmd_reg.h"

/**************************************************************************************************/
/* command: add */

static apr_status_t cmd_reg_add(md_cmd_ctx *ctx, const md_cmd_t *cmd)
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
    
    rv = md_reg_add(ctx->reg, md);
    if (APR_SUCCESS == rv) {
        md_cmd_print_md(ctx, md_reg_get(ctx->reg, md->name));
    }
    return rv;
}

md_cmd_t MD_RegAddCmd = {
    "add", MD_CTX_REG,  
    NULL, cmd_reg_add, MD_NoOptions, NULL,
    "add [opts] domain [domain...]", 
    "Adds a new mananged domain. Must not overlap with existing domains.", 
};

/**************************************************************************************************/
/* command: list */

static int list_add_md(void *baton, md_reg_t *reg, const md_t *md)
{
    apr_array_header_t *mdlist = baton;
    const md_t **pmd;
    
    pmd = (const md_t **)apr_array_push(mdlist);
    *pmd = md;
    return 1;
}

static int md_name_cmp(const void *v1, const void *v2)
{
    return strcmp(((const md_t*)v1)->name, ((const md_t*)v2)->name);
}

static apr_status_t cmd_reg_list(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_array_header_t *mdlist = apr_array_make(ctx->p, 5, sizeof(md_t *));
    apr_hash_t *mds = apr_hash_make(ctx->p);
    apr_status_t rv;
    int i, j;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "list do");
    md_reg_do(list_add_md, mdlist, ctx->reg);
    qsort(mdlist->elts, mdlist->nelts, sizeof(md_t *), md_name_cmp);
    
    for (i = 0; i < mdlist->nelts; ++i) {
        const md_t *md = APR_ARRAY_IDX(mdlist, i, const md_t*);
        md_cmd_print_md(ctx, md);
    }

    return APR_SUCCESS;
}

md_cmd_t MD_RegListCmd = {
    "list", MD_CTX_REG, 
    NULL, cmd_reg_list, MD_NoOptions, NULL,
    "list",
    "list all managed domains"
};

/**************************************************************************************************/
/* command: store update */

static apr_status_t cmd_reg_update(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    const char *name;
    const md_t *md;
    md_t *nmd;
    apr_status_t rv = APR_SUCCESS;
    int i, j, fields;
    
    if (ctx->argc <= 0) {
        return usage(cmd, "needs md name");
    }
    name = ctx->argv[0];
    
    md = md_reg_get(ctx->reg, name);
    if (NULL == md) {
        fprintf(stderr, "managed domain not found: %s\n", name);
        return APR_ENOENT;
    }

    /* update what */
    fields = 0;
    nmd = md_copy(ctx->p, md);
    if (NULL == md) {
        return APR_ENOMEM;
    }
    
    if (ctx->ca_url && (nmd->ca_url == NULL || strcmp(ctx->ca_url, nmd->ca_url))) {
        nmd->ca_url = ctx->ca_url;
        fields |= MD_UPD_CA_URL;
    }
    
    if (ctx->argc > 1) {
        const char *aspect = ctx->argv[1];
        
        if (!strcmp("domains", aspect)) {
            nmd->domains = md_cmd_gather_args(ctx, 2);
            
            if (apr_is_empty_array(nmd->domains)) {
                fprintf(stderr, "update domains needs at least 1 domain name as parameter\n");
                return APR_EGENERAL;
            }
            fields |= MD_UPD_DOMAINS;
        }
        if (!strcmp("ca", aspect)) {
            if (ctx->argc <= 2) {
                usage(cmd, "update name ca <url> [proto]");
                return APR_EINVAL;
            }
            nmd->ca_url = ctx->argv[2];
            fields |= MD_UPD_CA_URL;
            if (ctx->argc > 3) {
                nmd->ca_proto = ctx->argv[3];
                fields |= MD_UPD_CA_PROTO;
            }
        }
        else {
            fprintf(stderr, "unknown update aspect: %s\n", aspect);
            return APR_ENOTIMPL;
        }
    }

    if (fields) {
        if (APR_SUCCESS == (rv = md_reg_update(ctx->reg, md->name, nmd, fields))) {
            md = md_reg_get(ctx->reg, md->name);
        }
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, ctx->p, "no changes necessary");
    }

    if (APR_SUCCESS == rv) {
        md_cmd_print_md(ctx, md);
    }
    return rv;
}

md_cmd_t MD_RegUpdateCmd = {
    "update", MD_CTX_REG, 
    NULL, cmd_reg_update, MD_NoOptions, NULL,
    "update name [ 'aspect' args ]",
    "update a managed domain's properties."
};


