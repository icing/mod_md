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

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_jws.h"
#include "md_http.h"

apr_status_t md_acme_init(apr_pool_t *p)
{
    return md_crypt_init(p);
}

apr_status_t md_acme_create(md_acme **pacme, apr_pool_t *p, const char *url)
{
    md_acme *acme;
    
    acme = apr_pcalloc(p, sizeof(*acme));
    if (!acme) {
        return APR_ENOMEM;
    }
    
    acme->url = url;
    acme->state = MD_ACME_S_INIT;
    acme->pool = p;
    *pacme = acme;
    
    return md_http_create(&acme->http, p);
}

apr_status_t md_acme_setup(md_acme *acme)
{
    apr_status_t status;
    md_json *json;
    
    status = md_json_http_get(&json, acme->pool, acme->http, acme->url);
    if (status == APR_SUCCESS) {
        acme->new_authz = md_json_gets(json, "new-authz", NULL);
        acme->new_cert = md_json_gets(json, "new-cert", NULL);
        acme->new_reg = md_json_gets(json, "new-reg", NULL);
        acme->revoke_cert = md_json_gets(json, "revoke-cert", NULL);
        if (acme->new_authz && acme->new_cert && acme->new_reg && acme->revoke_cert) {
            acme->state = MD_ACME_S_LIVE;
            return APR_SUCCESS;
        }
        acme->state = MD_ACME_S_INIT;
        status = APR_EINVAL;
    }
    return status;
}

static apr_status_t update_nonce(const md_http_response *res)
{
    md_acme *acme = res->req->baton;
    if (res->rv == APR_SUCCESS && res->headers) {
        acme->nonce = apr_table_get(res->headers, "Replay-Nonce");
        if (!acme->nonce) {
            return APR_EGENERAL;
        }
    }
    return res->rv;
}

static apr_status_t md_acme_new_nonce(md_acme *acme)
{
    apr_status_t status;
    long id;
    
    status = md_http_HEAD(acme->http, acme->new_reg, NULL, update_nonce, acme, &id);
    md_http_await(acme->http, id);
    return status;
}

typedef struct md_acme_req md_acme_req;

typedef apr_status_t md_acme_req_cb(md_acme_req *req, apr_status_t status);

struct md_acme_req {
    md_acme *acme;
    struct md_acme_acct *acct;
    apr_pool_t *pool;
    
    const char *url;
    apr_table_t *prot_hdrs;
    const char *payload;
    size_t payload_len;
    
    md_json *jws_req;

    md_json *jws_resp;
    apr_table_t *resp_hdrs;
    
    apr_status_t status;
    md_http_cb *on_done;
    void *baton;
};

static md_acme_req *md_acme_req_create(md_acme *acme, md_acme_acct *acct, const char *url)
{
    apr_pool_t *pool;
    md_acme_req *req;
    apr_status_t status;
    
    status = apr_pool_create(&pool, acme->pool);
    if (status != APR_SUCCESS) {
        return NULL;
    }
    
    req = apr_pcalloc(pool, sizeof(*req));
    if (!req) {
        apr_pool_destroy(pool);
        return NULL;
    }
        
    req->acme = acme;
    req->acct = acct;
    req->pool = pool;
    req->url = url;
    req->prot_hdrs = apr_table_make(pool, 5);
    if (!req->prot_hdrs) {
        apr_pool_destroy(pool);
        return NULL;
    }
    return req;
}
 
static apr_status_t on_response(const md_http_response *res)
{
    md_acme_req *req = res->req->baton;
    apr_status_t status = res->rv;
    
    fprintf(stderr, "recvd acme resp: %d %d\n", res->rv, res->status);
    if (status == APR_SUCCESS) {
        update_nonce(res);
        status = md_json_read_http(&req->jws_resp, req->pool, res);
        if (status == APR_SUCCESS) {
            
        }
    }
    
    req->status = status;
    return status;
}

static apr_status_t md_acme_req_done(md_acme_req *req)
{
    apr_status_t status = req->status;
    if (req->pool) {
        apr_pool_destroy(req->pool);
    }
    return status;
}

static apr_status_t md_acme_req_send(md_acme_req *req)
{
    apr_status_t status;

    if (!req->acme->nonce) {
        status = md_acme_new_nonce(req->acme);
        if (status != APR_SUCCESS) {
            return status;
        }
    }
    
    apr_table_set(req->prot_hdrs, "nonce", req->acme->nonce);
    req->acme->nonce = NULL;

    status = md_jws_sign(&req->jws_req, req->pool, req->payload, req->payload_len,
                         req->prot_hdrs, req->acct->key, NULL);
    if (status == APR_SUCCESS) {
        long id;
        const char *body;
        
        body = md_json_writep(req->jws_req, MD_JSON_FMT_COMPACT, req->pool);
        if (!body) {
            return APR_ENOMEM;
        }
        fprintf(stderr, "sending acme req: POST %s\n%s\n", req->url, body);
        status = md_http_POSTd(req->acme->http, req->url, NULL, "application/json",  
                               body, strlen(body), on_response, req, &id);
        md_http_await(req->acme->http, id);
        return md_acme_req_done(req);
    }
    return status;
}

apr_status_t md_acme_new_reg(md_acme *acme, const char *key_file, int key_bits)
{
    md_acme_req *req;
    md_json *jpayload;
    apr_status_t status;
    
    status = md_acme_acct_create(&acme->acct, acme->pool, key_file, key_bits);
    if (status != APR_SUCCESS) {
        return status;
    }
    
    req = md_acme_req_create(acme, acme->acct, acme->new_reg);
    if (req) {
        jpayload = md_json_create(req->pool);
        if (jpayload) {
            md_json_sets("new-reg", jpayload, "resource", NULL);
            req->payload = md_json_writep(jpayload, MD_JSON_FMT_COMPACT, req->pool);
        }
    }
        
    if (req->payload) {
        req->payload_len = strlen(req->payload);
        return md_acme_req_send(req);
    }
    return APR_ENOMEM;
}

