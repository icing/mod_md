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

apr_status_t md_reg_init(md_reg_t **preg, apr_pool_t *p, struct md_store_t *store)
{
    md_reg_t *reg;
    apr_status_t rv = APR_ENOMEM;
    
    reg = apr_pcalloc(p, sizeof(*reg));
    if (reg) {
        reg->p = p;
        reg->store = store;
        reg->mds = apr_hash_make(p);
        
        if (reg->mds) {
            rv = md_store_load(reg->store, reg->mds, reg->p);
        }
    }
    *preg = (rv == APR_SUCCESS)? reg : NULL;
    return rv;
}

apr_status_t md_reg_add(md_reg_t *reg, md_t *md)
{
    return APR_ENOTIMPL;
}

const md_t *md_reg_get(const md_reg_t *reg, const char *name)
{
    return apr_hash_get(reg->mds, name, strlen(name));
}

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
} find_overlap_ctx;

static int find_overlap(void *baton, const md_reg_t *reg, const md_t *md)
{
    find_overlap_ctx *ctx = baton;
    
    if (md_domains_overlap(ctx->md_checked, md)) {
        ctx->md = md;
        return 0;
    }
    return 1;
}

const md_t *md_reg_find_overlap(const md_reg_t *reg, const md_t *md)
{
    find_overlap_ctx ctx;
    
    ctx.md_checked = md;
    ctx.md = NULL;
    
    md_reg_do(find_overlap, &ctx, reg);
    return ctx.md;
}
