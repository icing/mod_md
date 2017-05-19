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

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_buckets.h>
#include <apr_hash.h>

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_jws.h"
#include "md_http.h"
#include "md_log.h"
#include "md_util.h"

#define MD_DIRNAME_ACCOUNTS "accounts"
#define MD_FILENAME_CA "ca.json"

typedef struct acme_problem_status_t acme_problem_status_t;

struct acme_problem_status_t {
    const char *type;
    apr_status_t rv;
};

static acme_problem_status_t Problems[] = {
};

static apr_status_t problem_status_get(const char *type) {
    int i;
    
    for(i = 0; i < (sizeof(Problems)/sizeof(Problems[0])); ++i) {
        if (!apr_strnatcasecmp(type, Problems[i].type)) {
            return Problems[i].rv;
        }
    }
    return APR_EGENERAL;
}

apr_status_t md_acme_init(apr_pool_t *p)
{
    return md_crypt_init(p);
}

apr_status_t md_acme_create(md_acme **pacme, apr_pool_t *p, const char *url, const char *path)
{
    md_acme *acme;
    apr_status_t rv;
    
    acme = apr_pcalloc(p, sizeof(*acme));
    if (acme) {
        acme->url = url;
        acme->path = path;
        acme->state = MD_ACME_S_INIT;
        acme->pool = p;
        acme->pkey_bits = 4096;
        acme->accounts = apr_hash_make(acme->pool);
    }
    
    if (!acme || !acme->accounts) {
        *pacme = NULL;
        return APR_ENOMEM;
    }

    if (acme->path) {
        char *acct_path, *ca_file;
        md_json *jca;
        
        rv = apr_filepath_merge(&acct_path, acme->path, MD_DIRNAME_ACCOUNTS, 
                                APR_FILEPATH_SECUREROOTTEST, acme->pool);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acme->pool, 
                          "invalid accounts path %s/%s", acme->path,  MD_DIRNAME_ACCOUNTS);
            return rv;
        }
        
        rv = apr_dir_make_recursive(acct_path, MD_FPROT_D_UONLY, acme->pool);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acme->pool, "mkdir %s", acme->path);
            return rv;
        }
        acme->acct_path = acct_path;
        
        
        rv = apr_filepath_merge(&ca_file, acme->path, MD_FILENAME_CA, 
                                APR_FILEPATH_SECUREROOTTEST, acme->pool);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acme->pool, 
                          "invalid ca file path %s/%s", acme->path,  MD_FILENAME_CA);
            return rv;
        }
        
        rv = md_json_readf(&jca, acme->pool, ca_file);
        if (APR_SUCCESS == rv) {
            const char *ca_url = md_json_gets(jca, "url", NULL);
            if (!ca_url) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, 
                    "url not found in CA file %s", ca_file);
                return APR_ENOENT;
            }
            else if (url && strcmp(ca_url, url)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, 
                    "url from CA file %s and given url differ: %s", ca_file, ca_url);
                return APR_EINVAL;
            }
            else {
                acme->url = ca_url;
            }
        }
        else if (APR_STATUS_IS_ENOENT(rv)) {
            if (!url) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, 
                    "need the server url for initializing the CA in: %s", path);
                return rv;
            }
        
            jca = md_json_create(acme->pool);
            md_json_sets(url, jca, "url", NULL);
            rv = md_json_fcreatex(jca, acme->pool, MD_JSON_FMT_INDENT, ca_file);
            if (APR_SUCCESS != rv) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acme->pool, "saving ca: %s", ca_file);
                return rv;
            }
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acme->pool, "reading ca: %s", ca_file);
            return rv;
        }
        
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, acme->pool,
                      "scanning for existing accounts at %s", acme->acct_path);
        rv = md_acme_acct_load(acme);
        if (APR_SUCCESS != rv) {
            return rv;
        }
    }
    
    *pacme = acme;
    return md_http_create(&acme->http, acme->pool);
}

apr_status_t md_acme_setup(md_acme *acme)
{
    apr_status_t rv;
    md_json *json;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, "get directory from %s", acme->url);
    
    rv = md_json_http_get(&json, acme->pool, acme->http, acme->url);
    if (APR_SUCCESS == rv) {
        acme->new_authz = md_json_gets(json, "new-authz", NULL);
        acme->new_cert = md_json_gets(json, "new-cert", NULL);
        acme->new_reg = md_json_gets(json, "new-reg", NULL);
        acme->revoke_cert = md_json_gets(json, "revoke-cert", NULL);
        if (acme->new_authz && acme->new_cert && acme->new_reg && acme->revoke_cert) {
            acme->state = MD_ACME_S_LIVE;
            return APR_SUCCESS;
        }
        acme->state = MD_ACME_S_INIT;
        rv = APR_EINVAL;
    }
    return rv;
}

/**************************************************************************************************/
/* acme requests */

static void req_update_nonce(md_acme_req *req)
{
    if (req->resp_hdrs) {
        const char *nonce = apr_table_get(req->resp_hdrs, "Replay-Nonce");
        if (nonce) {
            req->acme->nonce = nonce;
        }
    }
}

static apr_status_t http_update_nonce(const md_http_response *res)
{
    if (res->headers) {
        const char *nonce = apr_table_get(res->headers, "Replay-Nonce");
        if (nonce) {
            md_acme *acme = res->req->baton;
            acme->nonce = nonce;
        }
    }
    return res->rv;
}

static apr_status_t md_acme_new_nonce(md_acme *acme)
{
    apr_status_t rv;
    long id;
    
    rv = md_http_HEAD(acme->http, acme->new_reg, NULL, http_update_nonce, acme, &id);
    md_http_await(acme->http, id);
    return rv;
}

static md_acme_req *md_acme_req_create(md_acme *acme, const char *url)
{
    apr_pool_t *pool;
    md_acme_req *req;
    apr_status_t rv;
    
    rv = apr_pool_create(&pool, acme->pool);
    if (rv != APR_SUCCESS) {
        return NULL;
    }
    
    req = apr_pcalloc(pool, sizeof(*req));
    if (!req) {
        apr_pool_destroy(pool);
        return NULL;
    }
        
    req->acme = acme;
    req->pool = pool;
    req->url = url;
    req->prot_hdrs = apr_table_make(pool, 5);
    if (!req->prot_hdrs) {
        apr_pool_destroy(pool);
        return NULL;
    }
    return req;
}
 
static apr_status_t inspect_problem(md_acme_req *req, const md_http_response *res)
{
    const char *ctype;
    md_json *problem;
    
    ctype = apr_table_get(req->resp_hdrs, "content-type");
    if (ctype && !strcmp(ctype, "application/problem+json")) {
        /* RFC 7807 */
        md_json_read_http(&problem, req->pool, res);
        if (problem) {
            const char *ptype, *pdetail;
            
            req->resp_json = problem;
            ptype = md_json_gets(problem, "type", NULL); 
            pdetail = md_json_gets(problem, "detail", NULL);
            req->rv = problem_status_get(ptype);
             
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, req->rv, req->pool,
                          "acme problem %s: %s", ptype, pdetail);
            return req->rv;
        }
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, req->pool,
                  "acme problem unknonw: http status %d", res->status);
    return APR_EGENERAL;
}

static apr_status_t md_acme_req_done(md_acme_req *req)
{
    apr_status_t rv = req->rv;
    if (req->pool) {
        apr_pool_destroy(req->pool);
    }
    return rv;
}

static apr_status_t on_response(const md_http_response *res)
{
    md_acme_req *req = res->req->baton;
    const char *location;
    apr_status_t rv = res->rv;
    
    if (rv != APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, res->req->pool, "req failed");
        return rv;
    }
    
    req->resp_hdrs = apr_table_clone(req->pool, res->headers);
    req_update_nonce(req);
    
    /* TODO: Redirect Handling? */
    if (res->status >= 200 && res->status < 300) {
        location = apr_table_get(req->resp_hdrs, "location");
        if (!location) {
            if (res->status == 201) {
                md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, APR_EINVAL, req->pool, 
                              "201 response without location header");
                return APR_EINVAL;
            }
            location = req->url;
        }
        
        rv = md_json_read_http(&req->resp_json, req->pool, res);
        if (rv != APR_SUCCESS) {
                md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, req->pool, 
                              "unable to parse JSON response body");
                return APR_EINVAL;
        }
        
        if (md_log_is_level(req->pool, MD_LOG_TRACE2)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, req->pool,
                          "acme response: %s", md_json_writep(req->resp_json, 
                                                              MD_JSON_FMT_INDENT, req->pool));
        }
    
        if (req->on_success) {
            req->rv = rv;
            req->on_success(req->acme, location, req->resp_json, req->baton);
        }
    }
    else {
        req->rv = rv;
        rv = inspect_problem(req, res);
    }
    
    md_acme_req_done(req);
    return rv;
}

static apr_status_t md_acme_req_send(md_acme_req *req)
{
    apr_status_t rv;
    md_acme *acme = req->acme;

    if (!acme->nonce) {
        rv = md_acme_new_nonce(acme);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }
    
    apr_table_set(req->prot_hdrs, "nonce", acme->nonce);
    acme->nonce = NULL;

    rv = req->on_init(req, req->baton);
    
    if (rv == APR_SUCCESS) {
        long id;
        const char *body = NULL;
    
        if (req->req_json) {
            body = md_json_writep(req->req_json, MD_JSON_FMT_INDENT, req->pool);
            if (!body) {
                rv = APR_ENOMEM;
                goto out;
            }
        }
        
        if (body && md_log_is_level(req->pool, MD_LOG_TRACE2)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, req->pool, 
                          "req: POST %s, body:\n%s", req->url, body);
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, req->pool, 
                          "req: POST %s\n", req->url);
        }
        rv = md_http_POSTd(req->acme->http, req->url, NULL, "application/json",  
                               body, body? strlen(body) : 0, on_response, req, &id);
        req = NULL;
        md_http_await(acme->http, id);
    }
out:
    if (req) {
        md_acme_req_done(req);
    }
    return rv;
}

apr_status_t md_acme_req_do(md_acme *acme, const char *url,
                            md_acme_req_init_cb *on_init,
                            md_acme_req_success_cb *on_success,
                            void *baton)
{
    md_acme_req *req;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, acme->pool, "add acme req: %s", url);
    req = md_acme_req_create(acme, url);
    if (req) {
        req->on_init = on_init;
        req->on_success = on_success;
        req->baton = baton;
    
        return md_acme_req_send(req);
    }
    return APR_ENOMEM;
}

