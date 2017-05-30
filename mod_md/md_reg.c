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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "md.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"

/**************************************************************************************************/
/* life cycle */

apr_status_t md_reg_init(md_reg_t **preg, apr_pool_t *p, struct md_store_t *store)
{
    md_reg_t *reg;
    apr_status_t rv;
    
    reg = apr_pcalloc(p, sizeof(*reg));
    reg->p = p;
    reg->store = store;
    reg->mds = apr_hash_make(p);
    
    rv = md_store_load(reg->store, reg->mds, reg->p);
    *preg = (rv == APR_SUCCESS)? reg : NULL;
    return rv;
}

/**************************************************************************************************/
/* lookup */

const md_t *md_reg_get(const md_reg_t *reg, const char *name)
{
    return apr_hash_get(reg->mds, name, strlen(name));
}

typedef struct {
    const char *domain;
    const md_t *md;
} find_domain_ctx;

static int find_domain(void *baton, const md_reg_t *reg, const md_t *md)
{
    find_domain_ctx *ctx = baton;
    
    if (md_contains(md, ctx->domain)) {
        ctx->md = md;
        return 0;
    }
    return 1;
}

const md_t *md_reg_find(const md_reg_t *reg, const char *domain)
{
    find_domain_ctx ctx;

    ctx.domain = domain;
    ctx.md = NULL;
    
    md_reg_do(find_domain, &ctx, reg);
    return ctx.md;
}

typedef struct {
    const md_t *md_checked;
    const md_t *md;
    const char *s;
} find_overlap_ctx;

static int find_overlap(void *baton, const md_reg_t *reg, const md_t *md)
{
    find_overlap_ctx *ctx = baton;
    const char *overlap;
    
    if ((overlap = md_common_name(ctx->md_checked, md))) {
        ctx->md = md;
        ctx->s = overlap;
        return 0;
    }
    return 1;
}

const md_t *md_reg_find_overlap(const md_reg_t *reg, const md_t *md, const char **pdomain)
{
    find_overlap_ctx ctx;
    
    ctx.md_checked = md;
    ctx.md = NULL;
    ctx.s = NULL;
    
    md_reg_do(find_overlap, &ctx, reg);
    if (pdomain && ctx.s) {
        *pdomain = ctx.s;
    }
    return ctx.md;
}

/**************************************************************************************************/
/* iteration */

typedef struct {
    const md_reg_t *reg;
    md_reg_do_cb *cb;
    void *baton;
    const void *result;
} reg_do_ctx;

static int md_hash_do(void *baton, const void *key, apr_ssize_t klen, const void *value)
{
    reg_do_ctx *ctx = baton;
    return ctx->cb(ctx->baton, ctx->reg, value);
}

int md_reg_do(md_reg_do_cb *cb, void *baton, const md_reg_t *reg)
{
    reg_do_ctx ctx;
    
    ctx.reg = reg;
    ctx.cb = cb;
    ctx.baton = baton;
    return apr_hash_do(md_hash_do, &ctx, reg->mds);
}

/**************************************************************************************************/
/* manipulation */

apr_status_t md_reg_add(md_reg_t *reg, md_t *md)
{
    const md_t *other;
    const char *domain;
    apr_status_t rv;
    
    other = md_reg_find_overlap(reg, md, &domain);
    if (NULL != other) {
        if (md_contains_domains(other, md)) {
            if (md_equal_domains(md, other)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, APR_EEXIST, reg->p, 
                              "adding md %s has no effect. It already exists as %s", 
                              md->name, other->name);
                return APR_EEXIST;
            }
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, APR_EEXIST, reg->p, 
                          "adding md %s has no effect. All its domains are already in md %s", 
                          md->name, other->name);
            return APR_EEXIST;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, reg->p, 
                      "adding md %s denied. It shares domain '%s' names with md %s", 
                      md->name, domain, other->name);
        return APR_EINVAL;
    }
    rv = md_store_save_md(reg->store, md, 1);
    if (APR_SUCCESS == rv) {
        md_t *mine = md_clone(reg->p, md);
        apr_hash_set(reg->mds, mine->name, strlen(mine->name), mine);
    }
    return rv;
}

static apr_status_t p_md_update(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    apr_status_t rv = APR_SUCCESS;
    const char *name;
    const md_t *md;
    int fields, changed = 0;
    md_t *nmd;
    
    name = va_arg(ap, const char *);
    md = va_arg(ap, const md_t *);
    fields = va_arg(ap, int);
    
    if (NULL == (md = md_reg_get(reg, name))) {
        return APR_ENOENT;
    }
    nmd = md_copy(ptemp, md);
    if (MD_UPD_DOMAINS & fields) {
    }
    if (MD_UPD_CA_URL & fields) {
    }
    if (MD_UPD_CA_PROTO & fields) {
    }
    
    if (changed) {
        rv = md_store_save_md(reg->store, nmd, 0);
    }
    return rv;
}

apr_status_t md_reg_update(md_reg_t *reg, const char *name, const md_t *md, int fields)
{
    return md_util_pool_vdo(p_md_update, reg, reg->p, name, md, fields, NULL);
}

