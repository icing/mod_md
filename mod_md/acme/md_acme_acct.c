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

static apr_status_t acct_make(md_acme_acct_t **pacct, apr_pool_t *p, const char *ca_url, 
                              const char *id, apr_array_header_t *contacts,  
                              void *pkey)
{
    md_acme_acct_t *acct;
    
    acct = apr_pcalloc(p, sizeof(*acct));

    acct->id = id;
    acct->pool = p;
    acct->ca_url = ca_url;
    acct->key = pkey;
    
    if (!contacts || apr_is_empty_array(contacts)) {
        acct->contacts = apr_array_make(p, 5, sizeof(const char *));
    }
    else {
        acct->contacts = apr_array_copy(acct->pool, contacts);
    }
    
    *pacct = acct;
    return APR_SUCCESS;
}


static apr_status_t acct_create(md_acme_acct_t **pacct, apr_pool_t *p, md_acme_t *acme,  
                                apr_array_header_t *contacts, int key_bits)
{
    apr_status_t rv;
    md_pkey_t *pkey;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p, "generating new account key"); 
    rv = md_pkey_gen_rsa(&pkey, p, key_bits);
    if (rv == APR_SUCCESS) {
        rv = acct_make(pacct, p, acme->url, NULL, contacts, pkey);
    }
    return rv;
}

static void md_acme_acct_free(md_acme_acct_t *acct)
{
    if (acct->key) {
        md_pkey_free(acct->key);
        acct->key = NULL;
    }
}

/**************************************************************************************************/
/* json load/save */

static apr_status_t acct_save(md_acme_acct_t *acct, md_acme_t *acme)
{
    apr_pool_t *ptemp;
    const char *id;
    md_json_t *jacct;
    int i;
    apr_status_t rv;
    
    rv = apr_pool_create(&ptemp, acme->pool);
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

    id = acct->id;
    if (id) {
        rv = md_store_save_data(acme->store, MD_SG_ACCOUNTS, id, jacct, 0); 
    }
    else {
        /* meh! */
        rv = APR_EAGAIN;
        for (i = 0; i < 1000 && APR_SUCCESS != rv; ++i) {
            id = apr_psprintf(acme->pool, "%04d", i);
            rv = md_store_save_data(acme->store, MD_SG_ACCOUNTS, id, jacct, 1);
        }
        
        if (APR_SUCCESS == rv) {
            acct->id = id;
        }
    }
    
    if (APR_SUCCESS == rv) {
        rv = md_store_save_pkey(acme->store, MD_SG_ACCOUNTS, id, acct->key);
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
    
    rv = acct_make(pacct, p, ca_url, name, contacts, pkey);
    if (APR_SUCCESS == rv) {
        (*pacct)->url = url;
        (*pacct)->tos = md_json_gets(json, "terms-of-service", NULL);
        
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "load account %s (%s)", name, url);
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
    apr_status_t rv;
    
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
    
    rv = acme->store? acct_save(acct, acme) : APR_SUCCESS;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acct->pool, "updated acct %s", acct->url);
    return rv;
}

static apr_status_t acct_new(md_acme_acct_t **pacct, md_acme_t *acme, 
                             apr_array_header_t *contacts, const char *agreed_tos)
{
    md_acme_acct_t *acct;
    apr_status_t rv;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, "create new local account");
    rv = acct_create(&acct, acme->pool, acme, contacts, acme->pkey_bits);
    if (APR_SUCCESS != rv) {
        return rv;
    }
    if (agreed_tos) {
        acct->tos = agreed_tos;
    }
    
    rv = md_acme_req_do(acme, acme->new_reg, on_init_acct_new, on_success_acct_upd, acct);
    if (APR_SUCCESS == rv) {
        if (APR_SUCCESS == rv) {
            *pacct = acct;
            
            return APR_SUCCESS;
        }
    }
    *pacct = NULL;
    md_acme_acct_free(acct);
    return rv;
}

apr_status_t md_acme_register(md_acme_acct_t **pacct, md_acme_t *acme, 
                              apr_array_header_t *contacts, const char *agreed_tos)
{
    apr_status_t rv = acct_new(pacct, acme, contacts, agreed_tos);
    if (rv == APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, acme->pool, 
                      "registered new account %s", (*pacct)->url);
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

