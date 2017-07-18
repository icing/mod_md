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

#include <assert.h>
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
#include "md_json.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"

#include "acme/md_acme.h"
#include "acme/md_acme_acct.h"

struct md_reg_t {
    struct md_store_t *store;
    struct apr_hash_t *protos;
};

/**************************************************************************************************/
/* life cycle */

apr_status_t md_reg_init(md_reg_t **preg, apr_pool_t *p, struct md_store_t *store)
{
    md_reg_t *reg;
    apr_status_t rv;
    
    reg = apr_pcalloc(p, sizeof(*reg));
    reg->store = store;
    reg->protos = apr_hash_make(p);
    
    rv = md_acme_protos_add(reg->protos, p);
    *preg = (rv == APR_SUCCESS)? reg : NULL;
    return rv;
}

struct md_store_t *md_reg_store_get(md_reg_t *reg)
{
    return reg->store;
}

/**************************************************************************************************/
/* checks */

static apr_status_t check_values(md_reg_t *reg, apr_pool_t *p, const md_t *md, int fields)
{
    apr_status_t rv = APR_SUCCESS;
    const char *err = NULL;
    
    if (MD_UPD_DOMAINS & fields) {
        const md_t *other;
        const char *domain;
        int i;
        
        if (!md->domains || md->domains->nelts <= 0) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, APR_EINVAL, p, 
                          "empty domain list: %s", md->name);
            return APR_EINVAL;
        }
        
        for (i = 0; i < md->domains->nelts; ++i) {
            domain = APR_ARRAY_IDX(md->domains, i, const char *);
            if (!md_util_is_dns_name(p, domain, 1)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                              "md %s with invalid domain name: %s", md->name, domain);
                return APR_EINVAL;
            }
        }

        if (NULL != (other = md_reg_find_overlap(reg, md, &domain, p))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "md %s shares domain '%s' with md %s", 
                          md->name, domain, other->name);
            return APR_EINVAL;
        }
    }
    
    if (MD_UPD_CONTACTS & fields) {
        const char *contact;
        int i;

        for (i = 0; i < md->contacts->nelts && !err; ++i) {
            contact = APR_ARRAY_IDX(md->contacts, i, const char *);
            rv = md_util_abs_uri_check(p, contact, &err);
            
            if (err) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                              "contact for %s invalid (%s): %s", md->name, err, contact);
                return APR_EINVAL;
            }
        }
    }
    
    if ((MD_UPD_CA_URL & fields) && md->ca_url) { /* setting to empty is ok */
        rv = md_util_abs_uri_check(p, md->ca_url, &err);
        if (err) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "CA url for %s invalid (%s): %s", md->name, err, md->ca_url);
            return APR_EINVAL;
        }
    }
    
    if ((MD_UPD_CA_PROTO & fields) && md->ca_proto) { /* setting to empty is ok */
        /* Do we want to restrict this to "known" protocols? */
    }
    
    if ((MD_UPD_CA_ACCOUNT & fields) && md->ca_account) { /* setting to empty is ok */
        /* hmm, in case we know the protocol, some checks could be done */
    }

    if ((MD_UPD_AGREEMENT & fields) && md->ca_agreement) { /* setting to empty is ok */
        rv = md_util_abs_uri_check(p, md->ca_agreement, &err);
        if (err) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "CA url for %s invalid (%s): %s", md->name, err, md->ca_agreement);
            return APR_EINVAL;
        }
    }

    return rv;
}

/**************************************************************************************************/
/* state assessment */

static apr_status_t state_init(md_reg_t *reg, apr_pool_t *p, const md_t *md)
{
    md_state_t state = MD_S_UNKNOWN;
    const md_creds_t *creds;
    const md_cert_t *cert;
    apr_status_t rv;
    int i;

    if (APR_SUCCESS == (rv = md_reg_creds_get(&creds, reg, md, p))) {
        state = MD_S_INCOMPLETE;
        if (creds->cert && creds->pkey && creds->chain) {
            if (md_cert_has_expired(creds->cert)) {
                state = MD_S_EXPIRED;
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "md{%s}: cert expired", md->name);
                goto out;
            }
            if (!md_cert_is_valid_now(creds->cert)) {
                state = MD_S_ERROR;
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                              "md{%s}: cert not valid yet", md->name);
                goto out;
            }
            if (!md_cert_covers_md(creds->cert, md)) {
                state = MD_S_INCOMPLETE;
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                              "md{%s}: pending, cert does not cover all domains", md->name);
                goto out;
            }

            /* TODO: Do we consider an empty chain complete? */
            for (i = 0; i < creds->chain->nelts; ++i) {
                cert = APR_ARRAY_IDX(creds->chain, i, const md_cert_t *);
                if (!md_cert_is_valid_now(cert)) {
                    state = MD_S_EXPIRED;
                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                                  "md{%s}: chain cert #%d not valid", md->name, i);
                    goto out;
                }
            } 

            state = MD_S_COMPLETE;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "md{%s}: cert valid", md->name);
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "md{%s}: has cert=%d/pkey=%d/chain=%d", 
                          md->name, !!creds->cert, !!creds->pkey, !!creds->chain);
        }
    }

out:    
    if (APR_SUCCESS != rv) {
        state = MD_S_ERROR;
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "md{%s}{state}: %d", md->name, state);
    }
    /* break the constness, ugly but effective */
    ((md_t *)md)->state = state;
    return rv;
}

static apr_status_t state_vinit(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    md_t *md = va_arg(ap, md_t *);
    
    return state_init(reg, p, md);
}

apr_status_t md_reg_state_init(md_reg_t *reg, const md_t *md, apr_pool_t *p)
{
    return md_util_pool_vdo(state_vinit, reg, p, md, NULL);
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
    
    ctx->rv = state_init(reg, ctx->p, (md_t*)md);
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
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "initializing all md states");
    md_reg_do(state_ctx_init, &ctx, reg, p);
    return ctx.rv;
}

apr_status_t md_reg_states_init(md_reg_t *reg, int fail_early, apr_pool_t *p)
{
    return md_util_pool_vdo(states_vinit, reg, p, fail_early, NULL);
}

static const md_t *state_check(md_reg_t *reg, md_t *md, apr_pool_t *p) 
{
    if (md) {
        int ostate = md->state;
        if (APR_SUCCESS == state_init(reg, p, md) && md->state != ostate) {
            md_save(reg->store, p, MD_SG_DOMAINS, md, 0);
        }
    }
    return md;
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

static int reg_md_iter(void *baton, md_store_t *store, const md_t *md, apr_pool_t *ptemp)
{
    reg_do_ctx *ctx = baton;
    
    if (!ctx->exclude || strcmp(ctx->exclude, md->name)) {
        md = state_check(ctx->reg, (md_t*)md, ptemp);
        return ctx->cb(ctx->baton, ctx->reg, md);
    }
    return 1;
}

static int reg_do(md_reg_do_cb *cb, void *baton, md_reg_t *reg, apr_pool_t *p, const char *exclude)
{
    reg_do_ctx ctx;
    
    ctx.reg = reg;
    ctx.cb = cb;
    ctx.baton = baton;
    ctx.exclude = exclude;
    return md_store_md_iter(reg_md_iter, &ctx, reg->store, p, MD_SG_DOMAINS, "*");
}


int md_reg_do(md_reg_do_cb *cb, void *baton, md_reg_t *reg, apr_pool_t *p)
{
    return reg_do(cb, baton, reg, p, NULL);
}

/**************************************************************************************************/
/* lookup */

const md_t *md_reg_get(md_reg_t *reg, const char *name, apr_pool_t *p)
{
    md_t *md;
    
    if (APR_SUCCESS == md_load(reg->store, MD_SG_DOMAINS, name, &md, p)) {
        return state_check(reg, (md_t*)md, p);
    }
    return NULL;
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

const md_t *md_reg_find(md_reg_t *reg, const char *domain, apr_pool_t *p)
{
    find_domain_ctx ctx;

    ctx.domain = domain;
    ctx.md = NULL;
    
    md_reg_do(find_domain, &ctx, reg, p);
    return state_check(reg, (md_t*)ctx.md, p);
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

const md_t *md_reg_find_overlap(md_reg_t *reg, const md_t *md, const char **pdomain, apr_pool_t *p)
{
    find_overlap_ctx ctx;
    
    ctx.md_checked = md;
    ctx.md = NULL;
    ctx.s = NULL;
    
    reg_do(find_overlap, &ctx, reg, p, md->name);
    if (pdomain && ctx.s) {
        *pdomain = ctx.s;
    }
    return state_check(reg, (md_t*)ctx.md, p);
}

apr_status_t md_reg_get_cred_files(md_reg_t *reg, const md_t *md, apr_pool_t *p,
                                   const char **pkeyfile, const char **pcertfile,
                                   const char **pchainfile)
{
    apr_status_t rv;
    
    rv = md_store_get_fname(pkeyfile, reg->store, MD_SG_DOMAINS, md->name, MD_FN_PKEY, p);
    if (APR_SUCCESS == rv) {
        rv = md_store_get_fname(pcertfile, reg->store, MD_SG_DOMAINS, md->name, MD_FN_CERT, p);
    }
    if (APR_SUCCESS == rv) {
        rv = md_store_get_fname(pchainfile, reg->store, MD_SG_DOMAINS, md->name, MD_FN_CHAIN, p);
        if (APR_STATUS_IS_ENOENT(rv)) {
            *pchainfile = NULL;
            rv = APR_SUCCESS;
        }
    }
    return rv;
}

/**************************************************************************************************/
/* manipulation */

static apr_status_t p_md_add(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    apr_status_t rv = APR_SUCCESS;
    md_t *md, *mine;
    
    md = va_arg(ap, md_t *);
    mine = md_clone(ptemp, md);
    if (APR_SUCCESS == (rv = check_values(reg, ptemp, md, MD_UPD_ALL))
        && APR_SUCCESS == (rv = md_reg_state_init(reg, mine, ptemp))
        && APR_SUCCESS == (rv = md_save(reg->store, p, MD_SG_DOMAINS, mine, 1))) {
    }
    return rv;
}

apr_status_t md_reg_add(md_reg_t *reg, md_t *md, apr_pool_t *p)
{
    return md_util_pool_vdo(p_md_add, reg, p, md, NULL);
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
    
    if (NULL == (md = md_reg_get(reg, name, ptemp))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, APR_ENOENT, ptemp, "md %s", name);
        return APR_ENOENT;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "update md %s", name);
    
    if (APR_SUCCESS != (rv = check_values(reg, ptemp, updates, fields))) {
        return rv;
    }
    
    nmd = md_copy(ptemp, md);
    if (MD_UPD_DOMAINS & fields) {
        nmd->domains = updates->domains;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update domains: %s", name);
    }
    if (MD_UPD_CA_URL & fields) {
        nmd->ca_url = updates->ca_url;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update ca url: %s", name);
    }
    if (MD_UPD_CA_PROTO & fields) {
        nmd->ca_proto = updates->ca_proto;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update ca protocol: %s", name);
    }
    if (MD_UPD_CA_ACCOUNT & fields) {
        nmd->ca_account = updates->ca_account;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update account: %s", name);
    }
    if (MD_UPD_CONTACTS & fields) {
        nmd->contacts = updates->contacts;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update contacts: %s", name);
    }
    if (MD_UPD_AGREEMENT & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update agreement: %s", name);
        nmd->ca_agreement = updates->ca_agreement;
    }
    if (MD_UPD_CERT_URL & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update cert url: %s", name);
        nmd->cert_url = updates->cert_url;
    }
    if (MD_UPD_DRIVE_MODE & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update drive-mode: %s", name);
        nmd->drive_mode = updates->drive_mode;
    }
    
    if (fields && APR_SUCCESS == (rv = md_save(reg->store, p, MD_SG_DOMAINS, nmd, 0))) {
        rv = md_reg_state_init(reg, nmd, ptemp);
    }
    return rv;
}

apr_status_t md_reg_update(md_reg_t *reg, apr_pool_t *p, 
                           const char *name, const md_t *md, int fields)
{
    return md_util_pool_vdo(p_md_update, reg, p, name, md, fields, NULL);
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
    
    if (ok_or_noent(rv = md_cert_load(reg->store, MD_SG_DOMAINS, md->name, &cert, p))
        && ok_or_noent(rv = md_pkey_load(reg->store, MD_SG_DOMAINS, md->name, &pkey, p))
        && ok_or_noent(rv = md_chain_load(reg->store, MD_SG_DOMAINS, md->name, &chain, p))) {
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
                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, ptemp, 
                                  "md %s has unexpected cert state: %d", md->name, cert_state);
                    rv = APR_ENOTIMPL;
                    break;
            }
        }
    }
    *pcreds = (APR_SUCCESS == rv)? creds : NULL;
    return rv;
}

apr_status_t md_reg_creds_get(const md_creds_t **pcreds, md_reg_t *reg, 
                              const md_t *md, apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;
    md_creds_t *creds;
    
    rv = md_util_pool_vdo(creds_load, reg, p, &creds, md, NULL);
    *pcreds = (APR_SUCCESS == rv)? creds : NULL;
    return rv;
}

/**************************************************************************************************/
/* synching */

typedef struct {
    apr_pool_t *p;
    apr_array_header_t *conf_mds;
    apr_array_header_t *store_mds;
} sync_ctx;

static int find_changes(void *baton, md_store_t *store, const md_t *md, apr_pool_t *ptemp)
{
    sync_ctx *ctx = baton;

    APR_ARRAY_PUSH(ctx->store_mds, const md_t*) = md_clone(ctx->p, md);
    return 1;
}

/**
 * Procedure:
 * 1. Collect all defined "managed domains" (MD). It does not matter where a MD is defined. 
 *    All MDs need to be unique and have no overlaps in their domain names. 
 *    Fail the config otherwise. Also, if a vhost matches an MD, it
 *    needs to *only* have ServerAliases from that MD. There can be no more than one
 *    matching MD for a vhost. But an MD can apply to several vhosts.
 * 2. Synchronize with the persistent store. Iterate over all configured MDs and 
 *   a. create them in the store if they do not already exist, neither under the
 *      name or with a common domain.
 *   b. compare domain lists from store and config, if
 *      - store has dns name in other MD than from config, remove dns name from store def,
 *        issue WARNING.
 *      - store misses dns name from config, add dns name and update store
 *   c. compare MD acme url/protocol, update if changed
 */
apr_status_t md_reg_sync(md_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, 
                         apr_array_header_t *master_mds) 
{
    sync_ctx ctx;
    md_store_t *store = reg->store;
    apr_status_t rv;

    ctx.p = ptemp;
    ctx.conf_mds = master_mds;
    ctx.store_mds = apr_array_make(ptemp, 100, sizeof(md_t *));
    
    rv = md_store_md_iter(find_changes, &ctx, store, ptemp, MD_SG_DOMAINS, "*");
    if (APR_STATUS_IS_ENOENT(rv)) {
        rv = APR_SUCCESS;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                  "sync: found %d mds in store", ctx.store_mds->nelts);
    if (APR_SUCCESS == rv) {
        int i, added, fields;
        md_t *md, *config_md, *smd, *omd;
        const char *common;
        
        for (i = 0; i < ctx.conf_mds->nelts; ++i) {
            md = APR_ARRAY_IDX(ctx.conf_mds, i, md_t *);
            
            /* find the store md that is closest match for the configured md */
            smd = md_find_closest_match(ctx.store_mds, md);
            if (smd) {
                fields = 0;
                /* add any newly configured domains to the store md */
                added = md_array_str_add_missing(smd->domains, md->domains, 0);
                if (added) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                                 "%s: %d domains added", smd->name, added);
                    fields |= MD_UPD_DOMAINS;
                }
                
                /* Look for other store mds which have domains now being part of smd */
                while (APR_SUCCESS == rv && (omd = md_get_by_dns_overlap(ctx.store_mds, md))) {
                    /* find the name now duplicate */
                    common = md_common_name(md, omd);
                    assert(common);
                    
                    /* Is this md still configured or has it been abandoned in the config? */
                    config_md = md_get_by_name(ctx.conf_mds, omd->name);
                    if (config_md && md_contains(config_md, common)) {
                        /* domain used in two configured mds, not allowed */
                        rv = APR_EINVAL;
                        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                                      "domain %s used in md %s and %s", 
                                      common, md->name, omd->name);
                    }
                    else if (config_md) {
                        /* domain stored in omd, but no longer has the offending domain,
                           remove it from the store md. */
                        omd->domains = md_array_str_remove(ptemp, omd->domains, common, 0);
                        rv = md_reg_update(reg, ptemp, omd->name, omd, MD_UPD_DOMAINS);
                    }
                    else {
                        /* domain in a store md that is no longer configured, warn about it.
                         * Remove the domain here, so we can progress, but never save it. */
                        omd->domains = md_array_str_remove(ptemp, omd->domains, common, 0);
                        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                                      "domain %s, configured in md %s, is part of the stored md %s."
                                      " That md however is no longer mentioned in the config. "
                                      "If you longer want it, remove the md from the store.", 
                                      common, md->name, omd->name);
                    }
                }

                if (MD_SVAL_UPDATE(md, smd, ca_url)) {
                    smd->ca_url = md->ca_url;
                    fields |= MD_UPD_CA_URL;
                }
                if (MD_SVAL_UPDATE(md, smd, ca_proto)) {
                    smd->ca_proto = md->ca_proto;
                    fields |= MD_UPD_CA_PROTO;
                }
                if (MD_SVAL_UPDATE(md, smd, ca_agreement)) {
                    smd->ca_agreement = md->ca_agreement;
                    fields |= MD_UPD_AGREEMENT;
                }
                if (MD_VAL_UPDATE(md, smd, drive_mode)) {
                    smd->drive_mode = md->drive_mode;
                    fields |= MD_UPD_DRIVE_MODE;
                }
                if (!apr_is_empty_array(md->contacts) 
                    && !md_array_str_eq(md->contacts, smd->contacts, 0)) {
                    smd->contacts = md->contacts;
                    fields |= MD_UPD_CONTACTS;
                }
                
                if (fields) {
                    rv = md_reg_update(reg, ptemp, smd->name, smd, fields);
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "md %s updated", smd->name);
                }
            }
            else {
                /* new managed domain */
                rv = md_reg_add(reg, md, ptemp);
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "new md %s added", md->name);
            }
        }
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "loading mds");
    }
    
    return rv;
}


/**************************************************************************************************/
/* driving */

apr_status_t md_reg_staging_complete(md_reg_t *reg, const char *name, apr_pool_t *p) 
{
    apr_status_t rv;
    md_pkey_t *pkey, *acct_key;
    md_t *md;
    md_cert_t *cert;
    apr_array_header_t *chain;
    struct md_acme_acct_t *acct;

    /* Load all data which will be taken into the DOMAIN storage group.
     * This serves several purposes:
     *  1. It's a format check on the input data. 
     *  2. We write back what we read, creating data with our own access permissions
     *  3. We ignore any other accumulated data in STAGING
     *  4. Once TMP is verified, we can swap/archive groups with a rename
     *  5. Reading/Writing the data will apply/remove any group specific data encryption.
     *     With the exemption that DOMAINS and TMP must apply the same policy/keys.
     */
    if (APR_SUCCESS != (rv = md_load(reg->store, MD_SG_STAGING, name, &md, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: loading md json", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_cert_load(reg->store, MD_SG_STAGING, name, &cert, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: loading certificate", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_chain_load(reg->store, MD_SG_STAGING, name, &chain, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: loading cert chain", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_pkey_load(reg->store, MD_SG_STAGING, name, &pkey, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: loading staging private key", name);
        return rv;
    }

    /* See if staging holds a new or modified account */
    rv = md_acme_acct_load(&acct, &acct_key, reg->store, MD_SG_STAGING, name, p);
    if (APR_STATUS_IS_ENOENT(rv)) {
        acct = NULL;
        acct_key = NULL;
        rv = APR_SUCCESS;
    }
    else if (APR_SUCCESS != rv) {
        return rv; 
    }

    rv = md_store_purge(reg->store, p, MD_SG_TMP, name);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: error puring tmp storage", name);
        return rv;
    }
    
    if (acct) {
        md_acme_t *acme;
        
        if (APR_SUCCESS != (rv = md_acme_create(&acme, p, md->ca_url))
            || APR_SUCCESS != (rv = md_acme_acct_save(reg->store, p, acme, acct, acct_key))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: error saving acct", name);
            return rv;
        }
        md->ca_account = acct->id;
    }
    
    if (APR_SUCCESS != (rv = md_save(reg->store, p, MD_SG_TMP, md, 1))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: saving md json", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_cert_save(reg->store, p, MD_SG_TMP, name, cert, 1))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: saving certificate", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_chain_save(reg->store, p, MD_SG_TMP, name, chain, 1))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: saving cert chain", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_pkey_save(reg->store, p, MD_SG_TMP, name, pkey, 1))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: saving domain private key", name);
        return rv;
    }
    
    /* swap */
    rv = md_store_move(reg->store, p, MD_SG_TMP, MD_SG_DOMAINS, name, 1);
    if (APR_SUCCESS == rv) {
        /* archive the old directory and made staging the new one. Access the new
         * status of this md. */
        const md_t *md;
        
        md = md_reg_get(reg, name, p);
        if (!md) {
            rv = APR_ENOENT;
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                          "loading md after staging complete");
        }
        else if (md->state != MD_S_COMPLETE) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                          "md has state %d after staging complete", md->state);
        }
        
        md_store_purge(reg->store, p, MD_SG_STAGING, name);
        md_store_purge(reg->store, p, MD_SG_CHALLENGES, name);
    }

    return rv;
}

static apr_status_t run_driver(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    const md_proto_t *proto;
    const md_t *md;
    int reset;
    md_proto_driver_t *driver;
    apr_status_t rv;
    
    proto = va_arg(ap, const md_proto_t *);
    md = va_arg(ap, const md_t *);
    reset = va_arg(ap, int); 
    
    driver = apr_pcalloc(ptemp, sizeof(*driver));
    driver->proto = proto;
    driver->p = ptemp;
    driver->reg = reg;
    driver->store = md_reg_store_get(reg);
    driver->md = md;
    driver->reset = reset;
    
    if (APR_SUCCESS == (rv = proto->init(driver))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, 
                      "md %s driver run for proto %s", md->name, driver->proto->protocol);
        rv = proto->run(driver);
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, 
                  "md %s driver done for proto %s", md->name, driver->proto->protocol);
    return rv;
}

apr_status_t md_reg_drive(md_reg_t *reg, const md_t *md, int reset, apr_pool_t *p)
{
    const md_proto_t *proto;
    
    if (!md->ca_proto) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "md %s has no CA protocol", md->name);
        ((md_t *)md)->state = MD_S_ERROR;
        return APR_SUCCESS;
    }
    
    proto = apr_hash_get(reg->protos, md->ca_proto, strlen(md->ca_proto));
    if (!proto) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, 
                      "md %s has unknown CA protocol: %s", md->name, md->ca_proto);
        ((md_t *)md)->state = MD_S_ERROR;
        return APR_EINVAL;
    }
    
    return md_util_pool_vdo(run_driver, reg, p, proto, md, reset, NULL);
}
