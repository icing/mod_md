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

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_jws.h"
#include "md_log.h"
#include "md_util.h"
#include "md_version.h"

#define MD_ACME_ACCT_JSON_FMT_VERSION   0.01

static apr_status_t acct_make(md_acme_acct **pacct, apr_pool_t *p,
                              const char *name, apr_array_header_t *contacts,  
                              void *pkey)
{
    md_acme_acct *acct;
    
    acct = apr_pcalloc(p, sizeof(*acct));
    if (!acct) {
        if (pkey) {
            md_crypt_pkey_free(pkey);
        }
        return APR_ENOMEM;
    }

    acct->name = name;
    acct->pool = p;
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


apr_status_t md_acme_acct_create(md_acme_acct **pacct, apr_pool_t *p, 
                                 apr_array_header_t *contacts, int key_bits)
{
    apr_status_t status;
    md_pkey *pkey;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p, "generating new account key"); 
    status = md_crypt_pkey_gen_rsa(&pkey, p, key_bits);
    if (status == APR_SUCCESS) {
        status = acct_make(pacct, p, NULL, contacts, pkey);
    }
    return status;
}

void md_acme_acct_free(md_acme_acct *acct)
{
    if (acct->key) {
        md_crypt_pkey_free(acct->key);
        acct->key = NULL;
    }
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
        md_json_setsa(acct->contacts, jpayload, "contact", NULL);
        
        payload = md_json_writep(jpayload, MD_JSON_FMT_INDENT, req->pool);
        if (payload) {
            payload_len = strlen(payload);
            
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, req->pool, 
                          "acct_new payload(len=%d): %s", payload_len, payload);
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
    apr_array_clear(acct->contacts);
    md_json_getsa(acct->contacts, body, "contact", NULL);
    acct->registration = md_json_clone(acct->pool, body);
}

apr_status_t md_acme_acct_new(md_acme_acct **pacct, md_acme *acme, apr_array_header_t *contacts)
{
    md_acme_acct *acct;
    apr_status_t rv;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, "create new local account");
    rv = md_acme_acct_create(&acct, acme->pool, contacts, acme->pkey_bits);
    if (APR_SUCCESS != rv) {
        return rv;
    }
    
    rv = md_acme_req_do(acme, acme->new_reg, on_init_acct_new, on_success_acct_new, acct);
    if (APR_SUCCESS == rv) {
        rv = acme->acct_path? md_acme_acct_save(acct, acme) : APR_SUCCESS;
        if (APR_SUCCESS == rv) {
            apr_hash_set(acme->accounts, acct->url, strlen(acct->url), acct);
            *pacct = acct;
            
            return APR_SUCCESS;
        }
    }
    *pacct = NULL;
    md_acme_acct_free(acct);
    return rv;
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
}

apr_status_t md_acme_acct_del(md_acme *acme, md_acme_acct *acct)
{
    apr_status_t status;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, "delete account %s", acct->url);
    
    status = md_acme_req_do(acme, acct->url, on_init_acct_del, on_success_acct_del, acct);
    if (status == APR_SUCCESS) {
        apr_hash_set(acme->accounts, acct->url, strlen(acct->url), NULL);
        md_acme_acct_free(acct);
    }
    return status;
}

/**************************************************************************************************/
/* Account file persistence */

static apr_status_t mk_acct_paths(const char **pdata_file, const char **pkey_file, 
                                  apr_pool_t *p, md_acme *acme, const char *name)
{
    char *key_file = apr_psprintf(p, "%s.pem", name);
    char *data_file = apr_psprintf(p, "%s.json", name);
    apr_status_t rv;
    
    rv = apr_filepath_merge((char **)pdata_file, acme->acct_path, data_file, 
                            APR_FILEPATH_SECUREROOTTEST, p);
    if (APR_SUCCESS == rv) {
        rv = apr_filepath_merge((char **)pkey_file, acme->acct_path, key_file, 
                                APR_FILEPATH_SECUREROOTTEST, p);
    }
    return rv;
}

apr_status_t md_acme_acct_load(md_acme_acct **pacct, md_acme *acme, const char *name)
{
    md_json *json;
    apr_status_t rv;
    md_pkey *pkey;
    const char *data_path, *key_path;
    apr_array_header_t *contacts;
    const char *url;
    double version;
    
    rv = mk_acct_paths(&data_path, &key_path, acme->pool, acme, name);
    if (APR_SUCCESS == rv) {    
        rv = md_crypt_pkey_load_rsa(&pkey, acme->pool, key_path);
        if (APR_SUCCESS == rv) {
            rv = md_json_readf(&json, acme->pool, data_path);
            if (APR_SUCCESS != rv) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, 
                              "error reading account: %s", name);
                return APR_EINVAL;
            }
                
            version = md_json_getn(json, "version", NULL);
            if (version == 0.0) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, 
                              "account has no version: %s", name);
                return APR_EINVAL;
            }
            if (version > MD_ACME_ACCT_JSON_FMT_VERSION) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, 
                              "account has newer version %f, expecting %f: %s", 
                              version, MD_ACME_ACCT_JSON_FMT_VERSION, name);
                return APR_EINVAL;
            }
            
            url = md_json_gets(json, "url", NULL);
            if (!url) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, 
                              "account has no url: %s", name);
                return APR_EINVAL;
            }
            contacts = apr_array_make(acme->pool, 5, sizeof(const char *));
            md_json_getsa(contacts, json, "registration", "contact", NULL);
            rv = acct_make(pacct, acme->pool, name, contacts, pkey);
            if (APR_SUCCESS == rv) {
                (*pacct)->url = url;
                
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, 
                              "load account %s (%s)", name, url);
                apr_hash_set(acme->accounts, url, strlen(url), (*pacct));
            }
        }
    }
    return rv;
}

apr_status_t md_acme_acct_save(md_acme_acct *acct, md_acme *acme)
{
    apr_pool_t *ptemp;
    const char *name, *data_path, *key_path;
    int i;
    apr_file_t *f = NULL;
    apr_status_t rv;
    
    rv = apr_pool_create(&ptemp, acme->pool);
    if (APR_SUCCESS != rv) {
        return rv;
    }
    
    name = acct->name;
    if (name) {
        rv = mk_acct_paths(&data_path, &key_path, ptemp, acme, name);
        if (APR_SUCCESS == rv) {
            rv = apr_file_open(&f, data_path, APR_FOPEN_WRITE|APR_FOPEN_CREATE,
                               MD_FPROT_F_UONLY, ptemp);
        }
    }
    else {
        /* meh! */
        for (i = 0; i < 10000; ++i) {
            name = apr_psprintf(acme->pool, "%08d", i);
            rv = mk_acct_paths(&data_path, &key_path, ptemp, acme, name);
            if (APR_SUCCESS == rv) {
                rv = apr_file_open(&f, data_path, APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_EXCL,
                                   MD_FPROT_F_UONLY, ptemp);
                if (APR_SUCCESS == rv) {
                    break;
                }
            }
            name = NULL;
        }
        acct->name = name;
    }
    
    if (APR_SUCCESS == rv) {
        md_json *jacct;
        
        jacct = md_json_create(ptemp);
        md_json_sets(acct->url, jacct, "url", NULL);
        md_json_setn(MD_ACME_ACCT_JSON_FMT_VERSION, jacct, "version", NULL);
        md_json_setj(acct->registration, jacct, "registration", NULL);
        rv = md_json_writef(jacct, MD_JSON_FMT_INDENT, f);
        apr_file_close(f);
        
        if (APR_SUCCESS == rv) {
            rv = md_crypt_pkey_save(acct->key, ptemp, key_path);
        }
    }
    apr_pool_destroy(ptemp);
    return rv;
}

apr_status_t md_acme_acct_scan(md_acme *acme, const char *path)
{
    md_acme_acct *acct;
    apr_pool_t *ptemp;
    apr_int32_t info = (APR_FINFO_TYPE|APR_FINFO_NAME);
    apr_finfo_t finfo;
    apr_dir_t *dir;
    apr_status_t rv;
    char *name;
    
    rv = apr_pool_create(&ptemp, acme->pool);
    if (APR_SUCCESS != rv) {
        return rv;
    }
    if (APR_SUCCESS != (rv = apr_dir_open(&dir, path, ptemp))) {
        apr_pool_destroy(ptemp);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, acme->pool, "error opening dir %s", path);
        return rv;
    }
    
    while (APR_SUCCESS == (rv = apr_dir_read(&finfo, info, dir))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, acme->pool, "inspecting file %s", finfo.name);
        if (APR_REG == finfo.filetype 
            && (APR_SUCCESS == apr_fnmatch("*.json", finfo.name, 0))) {
            
            name = apr_pstrndup(ptemp, finfo.name, strlen(finfo.name)-5);
            rv = md_acme_acct_load(&acct, acme, name);
            if (APR_SUCCESS != rv) {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, acme->pool, 
                              "error loading account %s", name);
                break;
            }
        }
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, acme->pool, "closing dir %s", path);
    apr_dir_close(dir);
    apr_pool_destroy(ptemp);
    return APR_SUCCESS; 
}
