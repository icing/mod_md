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
#include <stdio.h>

#include <apr_lib.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "../md_json.h"
#include "../md_log.h"
#include "../md_jws.h"
#include "../md_store.h"
#include "../md_util.h"

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"

md_acme_authz_t *md_acme_authz_create(apr_pool_t *p)
{
    md_acme_authz_t *authz;
    authz = apr_pcalloc(p, sizeof(*authz));
    
    return authz;
}

md_acme_authz_set_t *md_acme_authz_set_create(apr_pool_t *p, const char *acct_id)
{
    md_acme_authz_set_t *authz_set;
    
    authz_set = apr_pcalloc(p, sizeof(*authz_set));
    authz_set->acct_id = acct_id;
    authz_set->authzs = apr_array_make(p, 5, sizeof(md_acme_authz_t *));
    
    return authz_set;
}

md_acme_authz_t *md_acme_authz_set_get(md_acme_authz_set_t *set, const char *domain)
{
    md_acme_authz_t *authz;
    int i;
    
    assert(domain);
    for (i = 0; i < set->authzs->nelts; ++i) {
        authz = APR_ARRAY_IDX(set->authzs, i, md_acme_authz_t *);
        if (!apr_strnatcasecmp(domain, authz->domain)) {
            return authz;
        }
    }
    return NULL;
}

apr_status_t md_acme_authz_set_add(md_acme_authz_set_t *set, md_acme_authz_t *authz)
{
    md_acme_authz_t *existing;
    
    assert(authz->domain);
    if (NULL != (existing = md_acme_authz_set_get(set, authz->domain))) {
        return APR_EINVAL;
    }
    APR_ARRAY_PUSH(set->authzs, md_acme_authz_t*) = authz;
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* Register a new authorization */

typedef struct {
    apr_pool_t *p;
    md_acme_t *acme;
    md_acme_acct_t *acct;
    const char *domain;
    md_acme_authz_t *authz;
} authz_ctx;

static apr_status_t on_init_authz(md_acme_req_t *req, void *baton)
{
    authz_ctx *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    md_json_sets("new-authz", jpayload, "resource", NULL);
    md_json_sets("dns", jpayload, "identifier", "type", NULL);
    md_json_sets(ctx->domain, jpayload, "identifier", "value", NULL);
    
    return md_acme_req_body_init(req, jpayload, ctx->acct->key);
} 

static apr_status_t on_success_authz(md_acme_t *acme, const apr_table_t *hdrs, 
                                     md_json_t *body, void *baton)
{
    authz_ctx *ctx = baton;
    const char *location = apr_table_get(hdrs, "location");
    apr_status_t rv = APR_SUCCESS;
    
    if (location) {
        ctx->authz = md_acme_authz_create(ctx->p);
        ctx->authz->domain = apr_pstrdup(ctx->p, ctx->domain);
        ctx->authz->location = apr_pstrdup(ctx->p, location);
        ctx->authz->resource = md_json_clone(ctx->p, body);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, ctx->p, "authz_new at %s", location);
    }
    else {
        rv = APR_EINVAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, ctx->p, "new authz, no location header");
    }
    return rv;
}

apr_status_t md_acme_authz_register(struct md_acme_authz_t **pauthz, md_acme_t *acme, 
                                    const char *domain, md_acme_acct_t *acct, apr_pool_t *p)
{
    apr_status_t rv;
    authz_ctx ctx;
    
    ctx.p = p;
    ctx.acme = acme;
    ctx.acct = acct;
    ctx.domain = domain;
    ctx.authz = NULL;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, "create new authz");
    rv = md_acme_req_do(acme, acme->new_authz, on_init_authz, on_success_authz, &ctx);
    *pauthz = (APR_SUCCESS == rv)? ctx.authz : NULL;
    return rv;
} 

/**************************************************************************************************/
/* authz conversion */

#define MD_KEY_DOMAIN           "domain"
#define MD_KEY_LOCATION         "location"

md_json_t *md_acme_authz_to_json(md_acme_authz_t *a, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        md_json_sets(a->domain, json, MD_KEY_DOMAIN, NULL);
        md_json_sets(a->location, json, MD_KEY_LOCATION, NULL);
        return json;
    }
    return NULL;
}

md_acme_authz_t *md_acme_authz_from_json(struct md_json_t *json, apr_pool_t *p)
{
    md_acme_authz_t *authz = md_acme_authz_create(p);
    if (authz) {
        authz->domain = md_json_dups(p, json, MD_KEY_DOMAIN, NULL);            
        authz->location = md_json_dups(p, json, MD_KEY_LOCATION, NULL);            
        return authz;
    }
    return NULL;
}

/**************************************************************************************************/
/* authz_set conversion */

#define MD_KEY_ACCOUNT          "account"
#define MD_KEY_AUTHZS           "authorizations"

static apr_status_t authz_to_json(void *value, md_json_t *json, apr_pool_t *p)
{
    return md_json_setj(md_acme_authz_to_json(value, p), json, NULL);
}

static apr_status_t authz_from_json(void **pvalue, md_json_t *json, apr_pool_t *p)
{
    *pvalue = md_acme_authz_from_json(json, p);
    return APR_SUCCESS;
}

md_json_t *md_acme_authz_set_to_json(md_acme_authz_set_t *set, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        md_json_sets(set->acct_id, json, MD_KEY_ACCOUNT, NULL);
        md_json_seta(set->authzs, authz_to_json, json, MD_KEY_AUTHZS, NULL);
        return json;
    }
    return NULL;
}

md_acme_authz_set_t *md_acme_authz_set_from_json(md_json_t *json, apr_pool_t *p)
{
    md_acme_authz_set_t *set = md_acme_authz_set_create(p, NULL);
    if (set) {
        set->acct_id = md_json_dups(p, json, MD_KEY_ACCOUNT, NULL);            
        md_json_geta(set->authzs, authz_from_json, json, MD_KEY_AUTHZS, NULL);
        return set;
    }
    return NULL;
}

/**************************************************************************************************/
/* persistence */

#define MD_FN_AUTHZ     "authz.json"

apr_status_t md_acme_authz_set_load(struct md_store_t *store, const char *md_name, 
                                    md_acme_authz_set_t **pauthz_set, apr_pool_t *p)
{
    apr_status_t rv;
    md_json_t *json;
    md_acme_authz_set_t *authz_set;
    
    rv = md_store_load_json(store, MD_SG_DOMAINS, md_name, MD_FN_AUTHZ, &json, p);
    if (APR_SUCCESS == rv) {
        authz_set = md_acme_authz_set_from_json(json, p);
    }
    *pauthz_set = (APR_SUCCESS == rv)? authz_set : NULL;
    return rv;  
}

static apr_status_t p_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_t *store = baton;
    md_json_t *json;
    md_acme_authz_set_t *set;
    const char *md_name;
    int create;
    
    md_name = va_arg(ap, const char *);
    set = va_arg(ap, md_acme_authz_set_t *);
    create = va_arg(ap, int);

    json = md_acme_authz_set_to_json(set, ptemp);
    assert(json);
    assert(set->acct_id);
    return md_store_save_json(store, MD_SG_DOMAINS, md_name, MD_FN_AUTHZ, json, create);
}

apr_status_t md_acme_authz_set_save(struct md_store_t *store, const char *md_name, 
                                    md_acme_authz_set_t *authz_set, int create)
{
    return md_util_pool_vdo(p_save, store, store->p, md_name, authz_set, create, NULL);
}

