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
#include <apr_uri.h>

#include "md.h"
#include "md_crypt.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"

#include "acme/md_acme.h"

struct md_reg_t {
    apr_pool_t *p;
    struct md_store_t *store;
    struct apr_hash_t *protos;

    struct apr_hash_t *mds;
    struct apr_hash_t *creds;
};

/**************************************************************************************************/
/* life cycle */

apr_status_t md_reg_init(md_reg_t **preg, apr_pool_t *p, struct md_store_t *store)
{
    md_reg_t *reg;
    apr_status_t rv;
    apr_array_header_t *mds;
    
    reg = apr_pcalloc(p, sizeof(*reg));
    reg->p = p;
    reg->store = store;
    reg->protos = apr_hash_make(p);
    reg->mds = apr_hash_make(p);
    reg->creds = apr_hash_make(p);
    
    if (APR_SUCCESS == (rv = md_acme_protos_add(reg->protos, reg->p))) {
        mds = apr_array_make(p, 5, sizeof(md_t *));
        if (APR_SUCCESS == (rv = md_store_load_mds(mds, reg->store, reg->p))) {
            md_t *md;
            int i;
            
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, reg->p, "reg: %d mds loaded", mds->nelts);
            for (i = 0; i < mds->nelts; ++i) {
                md = APR_ARRAY_IDX(mds, i, md_t*);
                apr_hash_set(reg->mds, md->name, strlen(md->name), md);
            }
            
            rv = md_reg_states_init(reg, 0);
        }
    }

    *preg = (rv == APR_SUCCESS)? reg : NULL;
    return rv;
}

/**************************************************************************************************/
/* iteration */

typedef struct {
    md_reg_t *reg;
    md_reg_do_cb *cb;
    void *baton;
    const char *exclude;
    const void *result;
} reg_do_ctx;

static int md_hash_do(void *baton, const void *key, apr_ssize_t klen, const void *value)
{
    reg_do_ctx *ctx = baton;
    const md_t *md = value;
    
    if (!ctx->exclude || strcmp(ctx->exclude, md->name)) {
        return ctx->cb(ctx->baton, ctx->reg, md);
    }
    return 1;
}

static int reg_do(md_reg_do_cb *cb, void *baton, md_reg_t *reg, const char *exclude)
{
    reg_do_ctx ctx;
    
    ctx.reg = reg;
    ctx.cb = cb;
    ctx.baton = baton;
    ctx.exclude = exclude;
    return apr_hash_do(md_hash_do, &ctx, reg->mds);
}


int md_reg_do(md_reg_do_cb *cb, void *baton, md_reg_t *reg)
{
    return reg_do(cb, baton, reg, NULL);
}

/**************************************************************************************************/
/* checks */

static apr_status_t check_values(md_reg_t *reg, apr_pool_t *p, const md_t *md, int fields)
{
    apr_status_t rv = APR_SUCCESS;
    
    if (MD_UPD_DOMAINS & fields) {
        const md_t *other;
        const char *domain;
        int i;
        
        if (!md->domains || md->domains->nelts <= 0) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, APR_EINVAL, p, 
                          "empty domain list: %s", md->name);
            rv = APR_EINVAL; goto out;
        }
        
        for (i = 0; i < md->domains->nelts; ++i) {
            domain = APR_ARRAY_IDX(md->domains, i, const char *);
            if (!md_util_is_dns_name(p, domain, 1)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                              "md %s with invalid domain name: %s", md->name, domain);
                rv = APR_EINVAL; goto out;
            }
        }

        if (NULL != (other = md_reg_find_overlap(reg, md, &domain))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "md %s shares domain '%s' with md %s", 
                          md->name, domain, other->name);
            rv = APR_EINVAL; goto out;
        }
    }
    
    if ((MD_UPD_CA_URL & fields) && md->ca_url) { /* setting to empty is ok */
        apr_uri_t uri;
        
        if (APR_SUCCESS != (rv = apr_uri_parse(p, md->ca_url, &uri))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                          "parsing CA url for %s: %s", md->name, md->ca_url);
            goto out;
        }
        if (!uri.scheme) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "CA url for %s without scheme: %s", md->name, md->ca_url);
            rv = APR_EINVAL; goto out;
        }
        if (!uri.hostname) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "CA url for %s without hostname: %s", md->name, md->ca_url);
            rv = APR_EINVAL; goto out;
        }
        else if (!md_util_is_dns_name(p, uri.hostname, 0)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "CA url for %s invalid hostname: %s", md->name, md->ca_url);
            rv = APR_EINVAL; goto out;
        }
        if (uri.port_str && (uri.port == 0 || uri.port > 65353)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "CA url for %s invalid port: %s", md->name, md->ca_url);
            rv = APR_EINVAL; goto out;
        }
    }
    
    if ((MD_UPD_CA_PROTO & fields) && md->ca_proto) { /* setting to empty is ok */
        /* Do we want to restrict this to "known" protocols? */
    }
    
    if ((MD_UPD_CA_ACCOUNT & fields) && md->ca_account) { /* setting to empty is ok */
        /* hmm, in case we know the protocol, some checks could be done */
    }
out:
    return rv;
}

/**************************************************************************************************/
/* state assessment */

static apr_status_t state_init(md_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, const md_t *md)
{
    md_state_t state = MD_S_UNKNOWN;
    const md_creds_t *creds;
    apr_status_t rv;

    if (APR_SUCCESS == (rv = md_reg_creds_get(&creds, reg, md))) {
        state = (creds->cert && creds->pkey)? MD_S_COMPLETE : MD_S_INCOMPLETE;
    }
    /* break the constness, ugly but effective */
    ((md_t *)md)->state = state;
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, reg->p, "md{%s}{state}: %d", md->name, state);
    
    return rv;
}

static apr_status_t state_vinit(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    md_t *md = va_arg(ap, md_t *);
    
    return state_init(reg, p, ptemp, md);
}

apr_status_t md_reg_state_init(md_reg_t *reg, const md_t *md)
{
    return md_util_pool_vdo(state_vinit, reg, reg->p, md, NULL);
}

typedef struct {
    apr_pool_t *p;
    apr_pool_t *ptemp;
    int fail_early;
    apr_status_t rv;
} init_ctx;

static int state_ctx_init(void *baton, md_reg_t *reg, const md_t *md)
{
    init_ctx *ctx = baton;
    
    ctx->rv = state_init(reg, ctx->p, ctx->ptemp, (md_t*)md);
    return (!ctx->fail_early || (APR_SUCCESS == ctx->rv))? 1 : 0;
}

static apr_status_t states_vinit(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    init_ctx ctx;
    
    ctx.p = p;
    ctx.ptemp = ptemp;
    ctx.fail_early = va_arg(ap, int);
    ctx.rv = APR_SUCCESS;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, reg->p, "initializing all md states");
    md_reg_do(state_ctx_init, &ctx, reg);
    return ctx.rv;
}

apr_status_t md_reg_states_init(md_reg_t *reg, int fail_early)
{
    return md_util_pool_vdo(states_vinit, reg, reg->p, fail_early, NULL);
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

static int find_domain(void *baton, md_reg_t *reg, const md_t *md)
{
    find_domain_ctx *ctx = baton;
    
    if (md_contains(md, ctx->domain)) {
        ctx->md = md;
        return 0;
    }
    return 1;
}

const md_t *md_reg_find(md_reg_t *reg, const char *domain)
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

static int find_overlap(void *baton, md_reg_t *reg, const md_t *md)
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

const md_t *md_reg_find_overlap(md_reg_t *reg, const md_t *md, const char **pdomain)
{
    find_overlap_ctx ctx;
    
    ctx.md_checked = md;
    ctx.md = NULL;
    ctx.s = NULL;
    
    reg_do(find_overlap, &ctx, reg, md->name);
    if (pdomain && ctx.s) {
        *pdomain = ctx.s;
    }
    return ctx.md;
}

/**************************************************************************************************/
/* manipulation */

apr_status_t md_reg_add(md_reg_t *reg, md_t *md)
{
    md_t *mine;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = check_values(reg, reg->p, md, MD_UPD_ALL))
        && APR_SUCCESS == (rv = md_store_save_md(reg->store, md, 1))
        && APR_SUCCESS == (rv = md_store_load_md(&mine, reg->store, md->name, reg->p))) {
        apr_hash_set(reg->mds, mine->name, strlen(mine->name), mine);
        
        rv = md_reg_state_init(reg, mine);
    }
    return rv;
}

static apr_status_t p_md_update(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    apr_status_t rv = APR_SUCCESS;
    const char *name;
    const md_t *md, *updates;
    int fields;
    md_t *nmd;
    
    name = va_arg(ap, const char *);
    updates = va_arg(ap, const md_t *);
    fields = va_arg(ap, int);
    
    if (NULL == (md = md_reg_get(reg, name))) {
        return APR_ENOENT;
    }
    
    if (APR_SUCCESS != (rv = check_values(reg, ptemp, updates, fields))) {
        return rv;
    }
    
    nmd = md_copy(ptemp, md);
    if (MD_UPD_DOMAINS & fields) {
        nmd->domains = updates->domains;
    }
    if (MD_UPD_CA_URL & fields) {
        nmd->ca_url = updates->ca_url;
    }
    if (MD_UPD_CA_PROTO & fields) {
        nmd->ca_proto = updates->ca_proto;
    }
    
    if (fields 
        && APR_SUCCESS == (rv = md_store_save_md(reg->store, nmd, 0))
        && APR_SUCCESS == (rv = md_store_load_md(&nmd, reg->store, name, p))) {
        apr_hash_set(reg->mds, nmd->name, strlen(nmd->name), nmd);

        rv = md_reg_state_init(reg, nmd);
    }
    return rv;
}

apr_status_t md_reg_update(md_reg_t *reg, const char *name, const md_t *md, int fields)
{
    return md_util_pool_vdo(p_md_update, reg, reg->p, name, md, fields, NULL);
}

/**************************************************************************************************/
/* certificate related */

static int ok_or_noent(apr_status_t rv) 
{
    return (APR_SUCCESS == rv || APR_ENOENT == rv);
}

static apr_status_t creds_load(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    apr_status_t rv;
    md_cert_t *cert;
    md_pkey_t *pkey;
    apr_array_header_t *chain;
    md_creds_t *creds, **pcreds;
    const md_t *md;
    md_cert_state_t cert_state;
    
    pcreds = va_arg(ap, md_creds_t **);
    md = va_arg(ap, const md_t *);
    
    if (ok_or_noent(rv = md_store_load_cert(&cert, reg->store, md->name, p))
        && ok_or_noent(rv = md_store_load_pkey(&pkey, reg->store, MD_SG_DOMAINS, md->name, p))
        && ok_or_noent(rv = md_store_load_chain(&chain, reg->store, md->name, p))) {
        rv = APR_SUCCESS;
            
        creds = apr_pcalloc(p, sizeof(*creds));
        creds->cert = cert;
        creds->pkey = pkey;
        creds->chain = chain;
        
        if (creds->cert) {
            switch ((cert_state = md_cert_state_get(creds->cert))) {
                case MD_CERT_VALID:
                    creds->expired = 0;
                    break;
                case MD_CERT_EXPIRED:
                    creds->expired = 1;
                    break;
                default:
                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, reg->p, 
                                  "md %s has unexpcted certificae state: %d", md->name, cert_state);
                    rv = APR_ENOTIMPL;
                    break;
            }
        }
    }
    *pcreds = (APR_SUCCESS == rv)? creds : NULL;
    return rv;
}

apr_status_t md_reg_creds_get(const md_creds_t **pcreds, md_reg_t *reg, const md_t *md)
{
    apr_status_t rv = APR_ENOENT;
    md_creds_t *creds;
    
    creds = apr_hash_get(reg->creds, md->name, strlen(md->name));
    if (!creds) {
        if (APR_SUCCESS == (rv = md_util_pool_vdo(creds_load, reg, reg->p, &creds, md, NULL))) {
            apr_hash_set(reg->creds, md->name, strlen(md->name), creds);
        }
    }
    *pcreds = (APR_SUCCESS == rv)? creds : NULL;
    return rv;
}

/**************************************************************************************************/
/* driving */

static apr_status_t run_driver(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    const md_proto_t *proto;
    const md_t *md;
    md_proto_driver_t *driver;
    apr_status_t rv;
    
    proto = va_arg(ap, const md_proto_t *);
    md = va_arg(ap, const md_t *);
    
    
    driver = apr_pcalloc(ptemp, sizeof(*driver));
    driver->proto = proto;
    driver->p = ptemp;
    driver->reg = reg;
    driver->md = md;
    
    if (APR_SUCCESS == (rv = proto->init(driver))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, reg->p, 
                      "md %s driver run for proto %s", md->name, driver->proto->protocol);
        while (APR_EAGAIN == (rv = proto->run(driver))) {
            /* TODO: put some retry-after logic here, manage several drivers */
        }
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, reg->p, 
                  "md %s driver done for proto %s", md->name, driver->proto->protocol);
    return rv;
}

apr_status_t md_reg_drive(md_reg_t *reg, const md_t *md, apr_pool_t *p)
{
    const md_proto_t *proto;
    
    if (!md->ca_proto) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, reg->p, "md %s has no CA protocol", md->name);
        ((md_t *)md)->state = MD_S_ERROR;
        return APR_SUCCESS;
    }
    
    proto = apr_hash_get(reg->protos, md->ca_proto, strlen(md->ca_proto));
    if (!proto) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, reg->p, 
                      "md %s has unknown CA protocol: %s", md->name, md->ca_proto);
        ((md_t *)md)->state = MD_S_ERROR;
        return APR_SUCCESS;
    }
    
    return md_util_pool_vdo(run_driver, reg, p, proto, md, NULL);
}
