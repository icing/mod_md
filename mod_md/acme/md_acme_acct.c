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

#include "../md_crypt.h"
#include "../md_json.h"
#include "../md_jws.h"
#include "../md_log.h"
#include "../md_store.h"
#include "../md_util.h"
#include "../md_version.h"

#include "md_acme.h"
#include "md_acme_acct.h"

#define MD_ACME_ACCT_JSON_FMT_VERSION   0.01

#define MD_KEY_ID               "id"
#define MD_KEY_AGREEMENT        "agreement"
#define MD_KEY_CONTACT          "contact"
#define MD_KEY_URL              "url"
#define MD_KEY_CA_URL           "ca-url"
#define MD_KEY_DISABLED         "disabled"
#define MD_KEY_VERSION          "version"
#define MD_KEY_REGISTRATION     "registration"

#define MD_FN_ACCOUNT           "account.json"
#define MD_FN_PKEY              "account.key"

static apr_status_t acct_make(md_acme_acct_t **pacct, apr_pool_t *p, md_store_t *store,
                              const char *ca_url, const char *id, apr_array_header_t *contacts,  
                              void *pkey, int new_key)
{
    md_acme_acct_t *acct;
    
    acct = apr_pcalloc(p, sizeof(*acct));

    acct->id = id? apr_pstrdup(p, id) : NULL;
    acct->pool = p;
    acct->ca_url = ca_url;
    acct->key = pkey;
    acct->key_changed = new_key;
    acct->store = store;
    
    if (!contacts || apr_is_empty_array(contacts)) {
        acct->contacts = apr_array_make(p, 5, sizeof(const char *));
    }
    else {
        acct->contacts = apr_array_copy(acct->pool, contacts);
    }
    
    *pacct = acct;
    return APR_SUCCESS;
}


static void md_acme_acct_free(md_acme_acct_t *acct)
{
    if (acct->key) {
        md_pkey_free(acct->key);
        acct->key = NULL;
    }
}

static const char *mk_acct_id(apr_pool_t *p, md_acme_t *acme, int i)
{
    return apr_psprintf(p, "ACME-%s-%04d", acme->sname, i);
}

static const char *mk_acct_pattern(apr_pool_t *p, md_acme_t *acme)
{
    return apr_psprintf(p, "ACME-%s-*", acme->sname);
}
 
/**************************************************************************************************/
/* json load/save */

static apr_status_t acct_save(md_acme_acct_t *acct)
{
    apr_pool_t *ptemp;
    md_json_t *jacct;
    apr_status_t rv;
    
    rv = apr_pool_create(&ptemp, acct->pool);
    if (APR_SUCCESS != rv) {
        return rv;
    }
    
    jacct = md_json_create(ptemp);
    md_json_sets(acct->id, jacct, MD_KEY_ID, NULL);
    md_json_setb(acct->disabled, jacct, MD_KEY_DISABLED, NULL);
    md_json_sets(acct->url, jacct, MD_KEY_URL, NULL);
    md_json_sets(acct->ca_url, jacct, MD_KEY_CA_URL, NULL);
    md_json_setn(MD_ACME_ACCT_JSON_FMT_VERSION, jacct, MD_KEY_VERSION, NULL);
    md_json_setj(acct->registration, jacct, MD_KEY_REGISTRATION, NULL);
    if (acct->agreement) {
        md_json_sets(acct->agreement, jacct, MD_KEY_AGREEMENT, NULL);
    }

    assert(acct->id);
    if (APR_SUCCESS == (rv = md_store_save(acct->store, MD_SG_ACCOUNTS, acct->id, 
                                           MD_FN_ACCOUNT, MD_SV_JSON, jacct, 0))) {
        rv = md_store_save(acct->store, MD_SG_ACCOUNTS, acct->id, MD_FN_PKEY, 
                           MD_SV_PKEY, acct->key, 0);
    }
    
    apr_pool_destroy(ptemp);
    return rv;
}

static apr_status_t acct_create(md_acme_acct_t *acct, md_acme_t *acme)
{
    apr_pool_t *ptemp;
    const char *id;
    md_json_t *jacct;
    int i;
    apr_status_t rv;
    
    rv = apr_pool_create(&ptemp, acct->pool);
    if (APR_SUCCESS != rv) {
        return rv;
    }
    
    jacct = md_json_create(ptemp);
    md_json_sets(acct->url, jacct, MD_KEY_URL, NULL);
    md_json_sets(acct->ca_url, jacct, MD_KEY_CA_URL, NULL);
    md_json_setn(MD_ACME_ACCT_JSON_FMT_VERSION, jacct, MD_KEY_VERSION, NULL);
    md_json_setj(acct->registration, jacct, MD_KEY_REGISTRATION, NULL);
    if (acct->agreement) {
        md_json_sets(acct->agreement, jacct, MD_KEY_AGREEMENT, NULL);
    }

    rv = APR_EAGAIN;
    for (i = 0; i < 1000 && APR_SUCCESS != rv; ++i) {
        id = mk_acct_id(acct->pool, acme, i);
        md_json_sets(id, jacct, MD_KEY_ID, NULL);
        rv = md_store_save(acct->store, MD_SG_ACCOUNTS, id, 
                           MD_FN_ACCOUNT, MD_SV_JSON, jacct, 1);
    }
    
    if (APR_SUCCESS == rv) {
        acct->id = id;
    }
    
    if (APR_SUCCESS == rv) {
        rv = md_store_save(acct->store, MD_SG_ACCOUNTS, id, 
                           MD_FN_ACCOUNT, MD_SV_JSON, jacct, 1);
        rv = md_store_save(acct->store, MD_SG_ACCOUNTS, id, 
                           MD_FN_PKEY, MD_SV_PKEY, acct->key, 0);
        if (APR_SUCCESS == rv) {
            acct->key_changed = 0;
        }
    }
    
    apr_pool_destroy(ptemp);
    return rv;
}

apr_status_t md_acme_acct_load(md_acme_acct_t **pacct, md_store_t *store, const char *name,
                               apr_pool_t *p)
{
    md_json_t *json;
    apr_status_t rv;
    md_pkey_t *pkey;
    apr_array_header_t *contacts;
    const char *url, *ca_url;
    double version;
    int disabled;

    rv = md_store_load_json(store, MD_SG_ACCOUNTS, name, MD_FN_ACCOUNT, &json, p);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "error reading account: %s", name);
        return rv;
    }
    
    rv = md_store_load(store, MD_SG_ACCOUNTS, name, MD_FN_PKEY, MD_SV_PKEY, (void**)&pkey, p);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "loading key: %s", name);
        return rv;
    }
        
    version = md_json_getn(json, "version", NULL);
    if (version == 0.0) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "account has no version: %s", name);
        return APR_EINVAL;
    }
    if (version > MD_ACME_ACCT_JSON_FMT_VERSION) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p,
                      "account has newer version %f, expecting %f: %s", 
                      version, MD_ACME_ACCT_JSON_FMT_VERSION, name);
        return APR_EINVAL;
    }
    
    disabled = md_json_getb(json, MD_KEY_DISABLED, NULL);
    ca_url = md_json_gets(json, "ca-url", NULL);
    if (!ca_url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "account has no CA url: %s", name);
        return APR_EINVAL;
    }
    
    url = md_json_gets(json, "url", NULL);
    if (!url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "account has no url: %s", name);
        return APR_EINVAL;
    }

    contacts = apr_array_make(p, 5, sizeof(const char *));
    md_json_getsa(contacts, json, "registration", MD_KEY_CONTACT, NULL);
    
    rv = acct_make(pacct, p, store, ca_url, name, contacts, pkey, 0);
    if (APR_SUCCESS == rv) {
        (*pacct)->disabled = disabled;
        (*pacct)->url = url;
        (*pacct)->agreement = md_json_gets(json, "terms-of-service", NULL);
        
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "load account %s (%s)", name, url);
    }

    return rv;
}

/**************************************************************************************************/
/* Lookup */

typedef struct {
    apr_pool_t *p;
    md_acme_t *acme;
    apr_status_t rv;
    const char *id;
} find_ctx;

static int find_acct(void *baton, const char *name, const char *aspect,
                     md_store_vtype_t vtype, void *value)
{
    find_ctx *ctx = baton;
    md_json_t *json = value;
    int disabled;
    const char *ca_url, *id;
    
    id = md_json_gets(json, MD_KEY_ID, NULL);
    disabled = md_json_getb(json, MD_KEY_DISABLED, NULL);
    ca_url = md_json_gets(json, MD_KEY_CA_URL, NULL);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, 
                  "inspecting account %s for %s: %s, disabled=%d, ca-url=%s", 
                  name, ctx->acme->url, id, disabled, ca_url);
    if (!disabled && ca_url && !strcmp(ctx->acme->url, ca_url)) {
        ctx->id = id;
        return 0;
    }
    return 1;
}

apr_status_t md_acme_acct_find(md_acme_acct_t **pacct, 
                               md_store_t *store, md_acme_t *acme, apr_pool_t *p)
{
    apr_status_t rv;
    find_ctx ctx;
    
    ctx.p = p;
    ctx.acme = acme;
    ctx.rv = APR_SUCCESS;
    ctx.id = NULL;
    
    rv = md_store_iter(find_acct, &ctx, store, MD_SG_ACCOUNTS, mk_acct_pattern(p, acme),
                       MD_FN_ACCOUNT, MD_SV_JSON);
    if (APR_SUCCESS == rv) {
        if (ctx.id) {
            rv = md_acme_acct_load(pacct, store, ctx.id, p);
        }
        else {
            *pacct = NULL;
            rv = APR_ENOENT;
        }
    }
    if (APR_SUCCESS == rv || APR_EOF == rv) {
        rv = ctx.rv;
        if (APR_SUCCESS == rv && !ctx.id) {
            rv = APR_ENOENT;
        }
    }
    return rv;
}

/**************************************************************************************************/
/* Register a new account */

static apr_status_t on_init_acct_new(md_acme_req_t *req, void *baton)
{
    md_acme_acct_t *acct = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    md_json_sets("new-reg", jpayload, "resource", NULL);
    md_json_setsa(acct->contacts, jpayload, MD_KEY_CONTACT, NULL);
    if (acct->agreement) {
        md_json_sets(acct->agreement, jpayload, MD_KEY_AGREEMENT, NULL);
    }
    
    return md_acme_req_body_init(req, jpayload, acct->key);
} 

static apr_status_t on_success_acct_upd(md_acme_t *acme, const apr_table_t *hdrs, 
                                        md_json_t *body, void *baton)
{
    md_acme_acct_t *acct = baton;
    apr_status_t rv = APR_SUCCESS;
    
    if (!acct->url) {
        const char *location = apr_table_get(hdrs, "location");
        if (!location) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, APR_EINVAL, acct->pool, 
                          "new acct without location");
            return APR_EINVAL;
        }
        acct->url = apr_pstrdup(acct->pool, location);
    }
    if (!acct->tos_required) {
        acct->tos_required = md_link_find_relation(hdrs, acct->pool, "terms-of-service");
        if (acct->tos_required) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, 
                          "server requires agreement to <%s>", acct->tos_required);
        }
    }
    
    apr_array_clear(acct->contacts);
    md_json_getsa(acct->contacts, body, MD_KEY_CONTACT, NULL);
    acct->registration = md_json_clone(acct->pool, body);
    
    if (acct->store) {
        rv = acct->id? acct_save(acct) : acct_create(acct, acme);
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acct->pool, "updated acct %s", acct->url);
    return rv;
}

apr_status_t md_acme_register(md_acme_acct_t **pacct, md_store_t *store, md_acme_t *acme, 
                              apr_array_header_t *contacts, const char *agreement)
{
    md_acme_acct_t *acct;
    apr_status_t rv;
    md_pkey_t *pkey;
    const char *err = NULL, *uri;
    int i;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, "create new account");
    
    if (agreement) {
        if (APR_SUCCESS != (rv = md_util_abs_uri_check(acme->pool, agreement, &err))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, acme->pool, 
                          "invalid agreement uri (%s): %s", err, agreement);
        }
    }
    for (i = 0; i < contacts->nelts; ++i) {
        uri = APR_ARRAY_IDX(contacts, i, const char *);
        if (APR_SUCCESS != (rv = md_util_abs_uri_check(acme->pool, uri, &err))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, acme->pool, 
                          "invalid contact uri (%s): %s", err, uri);
        }
    }
    
    if (APR_SUCCESS == (rv = md_pkey_gen_rsa(&pkey, acme->pool, acme->pkey_bits))
        && APR_SUCCESS == (rv = acct_make(&acct,  acme->pool, store, 
                                          acme->url, NULL, contacts, pkey, 1))) {

        if (agreement) {
            acct->agreement = agreement;
        }

        rv = md_acme_req_do(acme, acme->new_reg, on_init_acct_new, on_success_acct_upd, acct);
        if (APR_SUCCESS == rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, acme->pool, 
                          "registered new account %s", acct->url);
        }
    }
    
    if (APR_SUCCESS != rv && acct) {
        md_acme_acct_free(acct);
        acct = NULL;
    }
    *pacct = acct;
    return rv;
}

/**************************************************************************************************/
/* validation */

static apr_status_t on_init_acct_valid(md_acme_req_t *req, void *baton)
{
    md_acme_acct_t *acct = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    md_json_sets("reg", jpayload, "resource", NULL);
    
    return md_acme_req_body_init(req, jpayload, acct->key);
} 

static apr_status_t on_success_acct_valid(md_acme_t *acme, const apr_table_t *hdrs, 
                                          md_json_t *body, void *baton)
{
    md_acme_acct_t *acct = baton;
    apr_status_t rv = APR_SUCCESS;
    const char *tos_required;
    
    apr_array_clear(acct->contacts);
    md_json_getsa(acct->contacts, body, MD_KEY_CONTACT, NULL);
    acct->registration = md_json_clone(acct->pool, body);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acct->pool, "validate acct %s: %s", 
                  acct->url, md_json_writep(body, MD_JSON_FMT_INDENT, acct->pool));
    
    acct->agreement = md_json_gets(acct->registration, MD_KEY_AGREEMENT, NULL);
    
    tos_required = md_link_find_relation(hdrs, acct->pool, "terms-of-service");
    if (tos_required) {
        if (!acct->agreement || strcmp(tos_required, acct->agreement)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acct->pool, 
                          "needs to agree to terms-of-service '%s', "
                          "has already agreed to '%s'", 
                          tos_required, acct->agreement);
        }
        acct->tos_required = tos_required;
    }
    
    return rv;
}

apr_status_t md_acme_acct_validate(md_acme_t *acme, md_acme_acct_t *acct)
{
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, "acct validation");
    return md_acme_req_do(acme, acct->url, on_init_acct_valid, on_success_acct_valid, acct);
}

/**************************************************************************************************/
/* terms-of-service */

static apr_status_t on_init_agree_tos(md_acme_req_t *req, void *baton)
{
    md_acme_acct_t *acct = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    md_json_sets("reg", jpayload, "resource", NULL);
    md_json_sets(acct->agreement, jpayload, MD_KEY_AGREEMENT, NULL);
    
    return md_acme_req_body_init(req, jpayload, acct->key);
} 

apr_status_t md_acme_acct_agree_tos(md_acme_t *acme, md_acme_acct_t *acct, const char *agreement)
{
    acct->agreement = agreement;
    return md_acme_req_do(acme, acct->url, on_init_agree_tos, on_success_acct_upd, acct);
}

static int agreement_required(md_acme_acct_t *acct)
{
    return (!acct->agreement 
            || (acct->tos_required && strcmp(acct->tos_required, acct->agreement)));
}

apr_status_t md_acme_acct_check_agreement(md_acme_t *acme, md_acme_acct_t *acct, 
                                          const char *agreement)
{
    apr_status_t rv = APR_SUCCESS;
    
    /* Check if (correct) Terms-of-Service for account were accepted */
    if (agreement_required(acct)) {
        const char *tos = acct->tos_required;
        if (!tos) {
            if (APR_SUCCESS != (rv = md_acme_acct_validate(acme, acct))) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acct->pool, 
                              "validate for account %", acct->id); 
                return rv;
            }
            tos = acct->tos_required; 
            if (!tos) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acct->pool, "unknown terms-of-service "
                              "required after validation of account %", acct->id); 
                return APR_EGENERAL;
            }
        }
        
        if (acct->agreement && !strcmp(tos, acct->agreement)) {
            rv = md_acme_acct_agree_tos(acme, acct, tos);
        }
        else if (agreement && !strcmp(tos, agreement)) {
            rv = md_acme_acct_agree_tos(acme, acct, tos);
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acct->pool, 
                          "need to accept terms-of-service <%s> for account %s", 
                          tos, acct->id);
            rv = APR_EACCES;
        }
    }
    return rv;
}        

/**************************************************************************************************/
/* Delete an existing account */

static apr_status_t on_init_acct_del(md_acme_req_t *req, void *baton)
{
    md_acme_acct_t *acct = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    md_json_sets("reg", jpayload, "resource", NULL);
    md_json_setb(1, jpayload, "delete", NULL);
    
    return md_acme_req_body_init(req, jpayload, acct->key);
} 

static apr_status_t on_success_acct_del(md_acme_t *acme, const apr_table_t *hdrs, md_json_t *body, void *baton)
{
    md_acme_acct_t *acct = baton;
    apr_status_t rv = APR_SUCCESS;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, acct->pool, "deleted account %s", acct->url);
    if (acct->store) {
        rv = md_store_remove(acct->store, MD_SG_ACCOUNTS, acct->id, MD_FN_ACCOUNT, acct->pool, 1);
        if (APR_SUCCESS == rv) {
            md_store_remove(acct->store, MD_SG_ACCOUNTS, acct->id, MD_FN_PKEY, acct->pool, 1);
        }
    }
    return rv;
}

apr_status_t md_acme_acct_del(md_acme_acct_t *acct)
{
    md_acme_t *acme;
    apr_status_t rv;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, "delete account %s from %s", 
                  acct->url, acct->ca_url);
    if (APR_SUCCESS == (rv = md_acme_create(&acme, acct->pool, acct->ca_url, acct->store))) {
        rv = md_acme_req_do(acme, acct->url, on_init_acct_del, on_success_acct_del, acct);
    }
    return rv;
}

apr_status_t md_acme_acct_disable(md_acme_acct_t *acct)
{
    apr_status_t rv = APR_SUCCESS;
    
    if (!acct->disabled) {
        acct->disabled = 1;
        rv = acct_save(acct);
    }
    return rv;
}

