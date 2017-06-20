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
#include <apr_buckets.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "../md.h"
#include "../md_json.h"
#include "../md_http.h"
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

apr_status_t md_acme_authz_set_remove(md_acme_authz_set_t *set, const char *domain)
{
    md_acme_authz_t *authz;
    int i;
    
    assert(domain);
    for (i = 0; i < set->authzs->nelts; ++i) {
        authz = APR_ARRAY_IDX(set->authzs, i, md_acme_authz_t *);
        if (!apr_strnatcasecmp(domain, authz->domain)) {
            int n = i +1;
            if (n < set->authzs->nelts) {
                void **elems = (void **)set->authzs->elts;
                memmove(elems + i, elems + n, set->authzs->nelts - n); 
            }
            --set->authzs->nelts;
            return APR_SUCCESS;
        }
    }
    return APR_ENOENT;
}

/**************************************************************************************************/
/* Register a new authorization */

typedef struct {
    size_t index;
    const char *type;
    const char *uri;
    const char *token;
    const char *key_authz;
} md_acme_authz_cha_t;

typedef struct {
    apr_pool_t *p;
    md_acme_t *acme;
    md_acme_acct_t *acct;
    const char *domain;
    md_acme_authz_t *authz;
    md_acme_authz_cha_t *challenge;
} authz_req_ctx;

static void authz_req_ctx_init(authz_req_ctx *ctx, md_acme_t *acme, md_acme_acct_t *acct, 
                               const char *domain, md_acme_authz_t *authz, apr_pool_t *p)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->p = p;
    ctx->acme = acme;
    ctx->acct = acct;
    ctx->domain = domain;
    ctx->authz = authz;
}

static apr_status_t on_init_authz(md_acme_req_t *req, void *baton)
{
    authz_req_ctx *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    md_json_sets("new-authz", jpayload, MD_KEY_RESOURCE, NULL);
    md_json_sets("dns", jpayload, MD_KEY_IDENTIFIER, MD_KEY_TYPE, NULL);
    md_json_sets(ctx->domain, jpayload, MD_KEY_IDENTIFIER, MD_KEY_VALUE, NULL);
    
    return md_acme_req_body_init(req, jpayload, ctx->acct->key);
} 

static apr_status_t on_success_authz(md_acme_t *acme, const apr_table_t *hdrs, 
                                     md_json_t *body, void *baton)
{
    authz_req_ctx *ctx = baton;
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
    authz_req_ctx ctx;
    
    authz_req_ctx_init(&ctx, acme, acct, domain, NULL, p);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, "create new authz");
    rv = md_acme_req_do(acme, acme->new_authz, on_init_authz, on_success_authz, &ctx);
    
    *pauthz = (APR_SUCCESS == rv)? ctx.authz : NULL;
    return rv;
}

/**************************************************************************************************/
/* Update an exiosting authorization */

apr_status_t md_acme_authz_update(md_acme_authz_t *authz, md_acme_t *acme, 
                                  md_acme_acct_t *acct, apr_pool_t *p)
{
    md_json_t *json;
    const char *s;
    apr_status_t rv;
    
    assert(acme);
    assert(acme->http);
    assert(authz);
    assert(authz->location);

    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, "update authz for %s at %s",
        authz->domain, authz->location);
        
    if (APR_SUCCESS == (rv = md_acme_get_json(&json, acme, authz->location, p))) {
        s = md_json_gets(json, "identifier", "type", NULL);
        if (!s || strcmp(s, "dns")) return APR_EINVAL;
        s = md_json_gets(json, "identifier", "value", NULL);
        if (!s || strcmp(s, authz->domain)) return APR_EINVAL;
        
        authz->state = MD_ACME_AUTHZ_S_UNKNOWN;
        s = md_json_gets(json, "status", NULL);
        if (s && !strcmp(s, "pending")) {
            authz->state = MD_ACME_AUTHZ_S_PENDING;
        }
        else if (s && !strcmp(s, "valid")) {
            authz->state = MD_ACME_AUTHZ_S_VALID;
        }
        else if (s && !strcmp(s, "invalid")) {
            authz->state = MD_ACME_AUTHZ_S_INVALID;
        }
        else if (s) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, acct->pool, "unknown authz state '%s' "
                          "for %s in %s", s, authz->domain, authz->location);
            return APR_EINVAL;
        }
    }
    return rv;
}

/**************************************************************************************************/
/* response to a challenge */

typedef struct {
    apr_pool_t *p;
    md_acme_t *acme;
    md_acme_acct_t *acct;
    md_acme_authz_t *authz;
    md_acme_authz_cha_t *http_01;
    md_acme_authz_cha_t *tls_sni_01;
} cha_find_ctx;

static md_acme_authz_cha_t *cha_from_json(apr_pool_t *p, size_t index, md_json_t *json)
{
    md_acme_authz_cha_t * cha;
    
    cha = apr_pcalloc(p, sizeof(*cha));
    cha->index = index;
    cha->type = md_json_dups(p, json, MD_KEY_TYPE, NULL);
    cha->uri = md_json_dups(p, json, MD_KEY_URI, NULL);
    cha->token = md_json_dups(p, json, MD_KEY_TOKEN, NULL);
    cha->key_authz = md_json_dups(p, json, MD_KEY_KEYAUTHZ, NULL);

    return cha;
}

static apr_status_t on_init_authz_resp(md_acme_req_t *req, void *baton)
{
    authz_req_ctx *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    /*md_json_sets(ctx->challenge->type, jpayload, MD_KEY_TYPE, NULL);*/
    md_json_sets("challenge", jpayload, MD_KEY_RESOURCE, NULL);
    md_json_sets(ctx->challenge->key_authz, jpayload, MD_KEY_KEYAUTHZ, NULL);
    
    return md_acme_req_body_init(req, jpayload, ctx->acct->key);
} 

static apr_status_t on_success_authz_resp(md_acme_t *acme, const apr_table_t *hdrs, 
                                          md_json_t *body, void *baton)
{
    authz_req_ctx *ctx = baton;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, ctx->p, "updated authz %s", ctx->authz->location);
    return APR_SUCCESS;
}

static apr_status_t cha_http_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                                      md_acme_t *acme, md_acme_acct_t *acct, 
                                      md_store_t *store, apr_pool_t *p)
{
    const char *thumb64, *key_authz, *data;
    apr_status_t rv;
    int notify_server = 0;
    
    assert(acct);
    assert(acct->key);
    assert(cha);
    assert(cha->token);
    
    if (APR_SUCCESS == (rv = md_jws_pkey_thumb(&thumb64, p, acct->key))) {
        key_authz = apr_psprintf(p, "%s.%s", cha->token, thumb64);
        if (cha->key_authz) {
            if (strcmp(key_authz, cha->key_authz)) {
                /* Hu? Did the account change key? */
                cha->key_authz = NULL;
            }
        }
        if (!cha->key_authz) {
            cha->key_authz = key_authz;
            notify_server = 1;
        }
    }
    
    rv = md_store_load(store, MD_SG_CHALLENGES, authz->domain, MD_FN_HTTP01,
                       MD_SV_TEXT, (void**)&data, p);
    if ((APR_SUCCESS == rv && strcmp(key_authz, data)) 
        || APR_STATUS_IS_ENOENT(rv)) {
        rv = md_store_save(store, MD_SG_CHALLENGES, authz->domain, MD_FN_HTTP01,
                           MD_SV_TEXT, (void*)key_authz, 0);
        notify_server = 1;
    }
    
    if (APR_SUCCESS == rv && notify_server) {
        authz_req_ctx ctx;

        /* challenge is setup or was changed from previous data, tell ACME server
         * so it may (re)try verification */        
        authz_req_ctx_init(&ctx, acme, acct, NULL, authz, p);
        ctx.challenge = cha;
        rv = md_acme_req_do(acme, cha->uri, on_init_authz_resp, on_success_authz_resp, &ctx);
    }
    return rv;
}

static apr_status_t cha_tls_sni_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                                         md_acme_t *acme, md_acme_acct_t *acct, 
                                         md_store_t *store, apr_pool_t *p)
{
    return APR_ENOTIMPL;
}

static apr_status_t add_candidates(void *baton, size_t index, md_json_t *json)
{
    cha_find_ctx *ctx = baton;
    
    const char *ctype = md_json_gets(json, MD_KEY_TYPE, NULL);
    if (ctype) {
        if (ctx->acme->can_cha_http_01 && !strcmp(MD_AUTHZ_CHA_HTTP, ctype)) {
            ctx->http_01 = cha_from_json(ctx->p, index, json);
        }
        else if (ctx->acme->can_cha_tls_sni_01 && !strcmp(MD_AUTHZ_CHA_SNI, ctype)) {
            ctx->tls_sni_01 = cha_from_json(ctx->p, index, json);
        }
    }
    return 1;
}

apr_status_t md_acme_authz_respond(md_acme_authz_t *authz, md_acme_t *acme, 
                                   md_acme_acct_t *acct, md_store_t *store,
                                   apr_pool_t *p)
{
    apr_status_t rv;
    cha_find_ctx fctx;
    
    assert(authz);
    assert(authz->resource);

    memset(&fctx, 0, sizeof(fctx));
    fctx.p = p;
    fctx.acme = acme;
    fctx.acct = acct;
    fctx.authz = authz;
    
    md_json_itera(add_candidates, &fctx, authz->resource, MD_KEY_CHALLENGES, NULL);
    
    if (fctx.http_01) {
        rv = cha_http_01_setup(fctx.http_01, authz, acme, acct, store, p);
    }
    else if (fctx.tls_sni_01) {
        rv = cha_tls_sni_01_setup(fctx.tls_sni_01, authz, acme, acct, store, p);
    }
    else {
        rv = APR_ENOTIMPL;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: no supported challenge found in %s",
                      authz->domain, authz->location);
    }
    return rv;
}

/**************************************************************************************************/
/* Delete an existing authz resource */

typedef struct {
    apr_pool_t *p;
    md_acme_acct_t *acct;
    md_acme_authz_t *authz;
} del_ctx;

static apr_status_t on_init_authz_del(md_acme_req_t *req, void *baton)
{
    authz_req_ctx *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    md_json_sets("deactivated", jpayload, MD_KEY_STATUS, NULL);
    
    return md_acme_req_body_init(req, jpayload, ctx->acct->key);
} 

static apr_status_t on_success_authz_del(md_acme_t *acme, const apr_table_t *hdrs, 
                                         md_json_t *body, void *baton)
{
    authz_req_ctx *ctx = baton;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, ctx->p, "deleted authz %s", ctx->authz->location);
    return APR_SUCCESS;
}

apr_status_t md_acme_authz_del(md_acme_authz_t *authz, md_acme_t *acme, 
                               md_acme_acct_t *acct, apr_pool_t *p)
{
    authz_req_ctx ctx;
    
    ctx.p = p;
    ctx.acct = acct;
    ctx.authz = authz;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "delete authz for %s from %s", 
                  authz->domain, authz->location);
    return md_acme_req_do(acme, authz->location, on_init_authz_del, on_success_authz_del, &ctx);
}

/**************************************************************************************************/
/* authz conversion */

#define MD_KEY_DOMAIN           "domain"
#define MD_KEY_LOCATION         "location"
#define MD_KEY_STATE            "state"

md_json_t *md_acme_authz_to_json(md_acme_authz_t *a, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        md_json_sets(a->domain, json, MD_KEY_DOMAIN, NULL);
        md_json_sets(a->location, json, MD_KEY_LOCATION, NULL);
        md_json_setl(a->state, json, MD_KEY_STATE, NULL);
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
        authz->state = (int)md_json_getl(json, MD_KEY_STATE, NULL);            
        return authz;
    }
    return NULL;
}

/**************************************************************************************************/
/* authz_set conversion */

#define MD_KEY_ACCOUNT          "account"
#define MD_KEY_AUTHZS           "authorizations"

static apr_status_t authz_to_json(void *value, md_json_t *json, apr_pool_t *p, void *baton)
{
    return md_json_setj(md_acme_authz_to_json(value, p), json, NULL);
}

static apr_status_t authz_from_json(void **pvalue, md_json_t *json, apr_pool_t *p, void *baton)
{
    *pvalue = md_acme_authz_from_json(json, p);
    return APR_SUCCESS;
}

md_json_t *md_acme_authz_set_to_json(md_acme_authz_set_t *set, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        md_json_sets(set->acct_id, json, MD_KEY_ACCOUNT, NULL);
        md_json_seta(set->authzs, authz_to_json, NULL, json, MD_KEY_AUTHZS, NULL);
        return json;
    }
    return NULL;
}

md_acme_authz_set_t *md_acme_authz_set_from_json(md_json_t *json, apr_pool_t *p)
{
    md_acme_authz_set_t *set = md_acme_authz_set_create(p, NULL);
    if (set) {
        set->acct_id = md_json_dups(p, json, MD_KEY_ACCOUNT, NULL);            
        md_json_geta(set->authzs, authz_from_json, NULL, json, MD_KEY_AUTHZS, NULL);
        return set;
    }
    return NULL;
}

/**************************************************************************************************/
/* persistence */

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

