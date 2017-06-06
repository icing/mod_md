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
    md_json_sets(acct->url, jacct, "url", NULL);
    md_json_sets(acct->ca_url, jacct, "ca-url", NULL);
    md_json_setn(MD_ACME_ACCT_JSON_FMT_VERSION, jacct, "version", NULL);
    md_json_setj(acct->registration, jacct, "registration", NULL);
    if (acct->tos) {
        md_json_sets(acct->tos, jacct, "terms-of-service", NULL);
    }

    assert(acct->id);
    if (APR_SUCCESS == (rv = md_store_save_data(acct->store, MD_SG_ACCOUNTS, acct->id, jacct, 0))) {
        rv = md_store_save_pkey(acct->store, MD_SG_ACCOUNTS, acct->id, acct->key);
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
    md_json_sets(acct->url, jacct, "url", NULL);
    md_json_sets(acct->ca_url, jacct, "ca-url", NULL);
    md_json_setn(MD_ACME_ACCT_JSON_FMT_VERSION, jacct, "version", NULL);
    md_json_setj(acct->registration, jacct, "registration", NULL);
    if (acct->tos) {
        md_json_sets(acct->tos, jacct, "terms-of-service", NULL);
    }

    rv = APR_EAGAIN;
    for (i = 0; i < 1000 && APR_SUCCESS != rv; ++i) {
        id = mk_acct_id(acct->pool, acme, i);
        md_json_sets(id, jacct, "id", NULL);
        rv = md_store_save_data(acct->store, MD_SG_ACCOUNTS, id, jacct, 1);
    }
    
    if (APR_SUCCESS == rv) {
        acct->id = id;
    }
    
    if (APR_SUCCESS == rv) {
        rv = md_store_save_pkey(acct->store, MD_SG_ACCOUNTS, id, acct->key);
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

    rv = md_store_load_data(&json, store, MD_SG_ACCOUNTS, name, p);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "error reading account: %s", name);
        return APR_EINVAL;
    }
    
    rv = md_store_load_pkey(&pkey, store, MD_SG_ACCOUNTS, name, p);
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
    md_json_getsa(contacts, json, "registration", "contact", NULL);
    
    rv = acct_make(pacct, p, store, ca_url, name, contacts, pkey, 0);
    if (APR_SUCCESS == rv) {
        (*pacct)->url = url;
        (*pacct)->tos = md_json_gets(json, "terms-of-service", NULL);
        
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "load account %s (%s)", name, url);
    }

    return rv;
}

/**************************************************************************************************/
/* Lookup */

typedef struct {
    apr_pool_t *p;
    apr_status_t rv;
    md_acme_acct_t *acct;
} find_ctx;

static int find_acct(void *baton, const char *name, md_store_vtype_t vtype, void *value)
{
    find_ctx *ctx = baton;
    md_acme_acct_t *acct = value;
    
    if (!acct->disabled) {
        ctx->acct = acct;
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
    ctx.rv = APR_SUCCESS;
    ctx.acct = NULL;
    
    rv = md_store_iter(find_acct, &ctx, store, MD_SG_ACCOUNTS, mk_acct_pattern(p, acme),
                       MD_SV_JSON_DATA);
    if (APR_SUCCESS == rv || APR_EOF == rv) {
        rv = ctx.rv;
        if (APR_SUCCESS == rv && !ctx.acct) {
            rv = APR_ENOENT;
        }
    }
    *pacct = (APR_SUCCESS == rv)? ctx.acct : NULL; 
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
    md_json_setsa(acct->contacts, jpayload, "contact", NULL);
    if (acct->tos) {
        md_json_sets(acct->tos, jpayload, "agreement", NULL);
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
    if (!acct->tos) {
        acct->tos = md_link_find_relation(hdrs, acct->pool, "terms-of-service");
        if (acct->tos) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, 
                          "server links terms-of-service %s", acct->tos);
        }
    }
    
    apr_array_clear(acct->contacts);
    md_json_getsa(acct->contacts, body, "contact", NULL);
    acct->registration = md_json_clone(acct->pool, body);
    
    if (acct->store) {
        rv = acct->id? acct_save(acct) : acct_create(acct, acme);
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acct->pool, "updated acct %s", acct->url);
    return rv;
}

apr_status_t md_acme_register(md_acme_acct_t **pacct, md_store_t *store, md_acme_t *acme, 
                              apr_array_header_t *contacts, const char *agreed_tos)
{
    md_acme_acct_t *acct;
    apr_status_t rv;
    md_pkey_t *pkey;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, "create new account");
    
    if (APR_SUCCESS == (rv = md_pkey_gen_rsa(&pkey, acme->pool, acme->pkey_bits))
        && APR_SUCCESS == (rv = acct_make(&acct,  acme->pool, store, 
                                          acme->url, NULL, contacts, pkey, 1))) {

        if (agreed_tos) {
            acct->tos = agreed_tos;
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
    
    apr_array_clear(acct->contacts);
    md_json_getsa(acct->contacts, body, "contact", NULL);
    acct->registration = md_json_clone(acct->pool, body);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acct->pool, "validate acct %s: %s", 
                  acct->url, md_json_writep(body, MD_JSON_FMT_INDENT, acct->pool));
    return rv;
}

apr_status_t md_acme_acct_validate(md_acme_acct_t *acct)
{
    md_acme_t *acme;
    apr_status_t rv;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, "acct validation");
    
    if (APR_SUCCESS == (rv = md_acme_create(&acme, acct->pool, acct->ca_url, acct->store))) {
        rv = md_acme_req_do(acme, acct->url, on_init_acct_valid, on_success_acct_valid, acct);
    }
    return rv;
}

/**************************************************************************************************/
/* terms-of-service */


static apr_status_t on_init_acct_upd(md_acme_req_t *req, void *baton)
{
    md_acme_acct_t *acct = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    md_json_sets("reg", jpayload, "resource", NULL);
    md_json_sets(acct->tos, jpayload, "agreement", NULL);
    
    return md_acme_req_body_init(req, jpayload, acct->key);
} 

apr_status_t md_acme_acct_agree_tos(md_acme_acct_t *acct, const char *agreed_tos)
{
    md_acme_t *acme;
    apr_status_t rv;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, "agree to terms-of-service");
    
    if (APR_SUCCESS == (rv = md_acme_create(&acme, acct->pool, acct->ca_url, acct->store))) {
        rv = md_acme_req_do(acme, acct->url, on_init_acct_upd, on_success_acct_upd, acct);
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
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, acct->pool, "deleted account %s", acct->url);
    return APR_SUCCESS;
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

