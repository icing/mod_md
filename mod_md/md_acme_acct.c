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
#include <apr_strings.h>
#include <apr_tables.h>

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_jws.h"
#include "md_log.h"

static apr_status_t acct_make(md_acme_acct **pacct, apr_pool_t *p, 
                              apr_array_header_t *contact,  
                              void *pkey, const char *key_file)
{
    md_acme_acct *acct;
    
    acct = apr_pcalloc(p, sizeof(*acct));
    if (!acct) {
        if (pkey) {
            md_crypt_pkey_free(pkey);
        }
        return APR_ENOMEM;
    }

    acct->pool = p;
    acct->key_file = key_file;
    acct->key = pkey;
    if (!contact || apr_is_empty_array(contact)) {
        acct->contact = apr_array_make(p, 5, sizeof(const char *));
    }
    else {
        acct->contact = apr_array_copy(acct->pool, contact);
    }
    
    *pacct = acct;
    return APR_SUCCESS;
}


apr_status_t md_acme_acct_create(md_acme_acct **pacct, apr_pool_t *p, 
                                 apr_array_header_t *contact,  
                                 const char *key_file, int key_bits)
{
    apr_status_t status;
    md_pkey *pkey;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p, "generating new account key"); 
    status = md_crypt_pkey_gen_rsa(&pkey, p, key_bits);
    if (status == APR_SUCCESS) {
        if (key_file) {
            status = md_crypt_pkey_save(pkey, p, key_file);
            if (status != APR_SUCCESS) {
                md_crypt_pkey_free(pkey);
            }
        }
        if (status == APR_SUCCESS) {
            status = acct_make(pacct, p, contact, pkey, key_file);
        }
    }
    return status;
}

apr_status_t md_acme_acct_open(md_acme_acct **pacct, apr_pool_t *p, const char *key_file)
{
    apr_status_t status;
    md_pkey *pkey;
    
    status = md_crypt_pkey_load_rsa(&pkey, p, key_file);
    if (status == APR_SUCCESS) {
        apr_array_header_t *contact = apr_array_make(p, 5, sizeof(const char *));
        
        return acct_make(pacct, p, contact, pkey, key_file);
    }
    return status;
}

/**************************************************************************************************/
/* Register a new account */

static apr_status_t on_init_acct_new(md_acme_req *req, void *baton)
{
    md_acme_acct *acct = baton;
    md_json *jpayload;
    const char *payload;
    size_t payload_len;

    jpayload = md_json_create(req->pool);
    if (jpayload) {
        md_json_sets("new-reg", jpayload, "resource", NULL);
        md_json_setsa(acct->contact, jpayload, "contact", NULL);
        
        payload = md_json_writep(jpayload, MD_JSON_FMT_INDENT, req->pool);
        if (payload) {
            payload_len = strlen(payload);
            
            return md_jws_sign(&req->req_json, req->pool, payload, payload_len,
                               req->prot_hdrs, acct->key, NULL);
        }
    }
    return APR_ENOMEM;
} 

static void on_success_acct_new(md_acme *acme, const char *location, md_json *body, void *baton)
{
    md_acme_acct *acct = baton;
    
    acct->url = apr_pstrdup(acct->pool, location);
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, acct->pool, "registered new account %s", location);
    
    /* TODO save */
    md_acme_add_acct(acme, acct);
}

apr_status_t md_acme_acct_new(md_acme *acme, 
                              apr_array_header_t *contact,
                              const char *key_file, int key_bits)
{
    md_acme_acct *acct;
    apr_status_t status;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, "create new local account");
    status = md_acme_acct_create(&acct, acme->pool, contact, key_file, key_bits);
    if (status != APR_SUCCESS) {
        return status;
    }
    
    return md_acme_req_add(acme, acme->new_reg, on_init_acct_new, on_success_acct_new, acct);
}

/**************************************************************************************************/
/* Delete an existing account */

static apr_status_t on_init_acct_del(md_acme_req *req, void *baton)
{
    md_acme_acct *acct = baton;
    md_json *jpayload;
    const char *payload;
    size_t payload_len;

    jpayload = md_json_create(req->pool);
    if (jpayload) {
        md_json_sets("reg", jpayload, "resource", NULL);
        md_json_setb(1, jpayload, "delete", NULL);
        
        payload = md_json_writep(jpayload, MD_JSON_FMT_INDENT, req->pool);
        if (payload) {
            payload_len = strlen(payload);
            
            return md_jws_sign(&req->req_json, req->pool, payload, payload_len,
                               req->prot_hdrs, acct->key, NULL);
        }
    }
    return APR_ENOMEM;
} 

static void on_success_acct_del(md_acme *acme, const char *location, md_json *body, void *baton)
{
    md_acme_acct *acct = baton;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, acct->pool, "deleted account %s", acct->url);
    
    /* TODO delete files */
    md_acme_remove_acct(acme, acct);
}

apr_status_t md_acme_acct_del(md_acme *acme, const char *url)
{
    md_acme_acct *acct;
    
    acct = md_acme_get_acct(acme, url);
    if (!acct) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, APR_NOTFOUND, acme->pool, 
                      "account not found: %s", url);
        return APR_NOTFOUND;
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, "delete account %s", url);
    
    return md_acme_req_add(acme, url, on_init_acct_del, on_success_acct_del, acct);
}

