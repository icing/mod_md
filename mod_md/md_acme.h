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

#ifndef mod_md_md_acme_h
#define mod_md_md_acme_h

struct apr_array_header_t;
struct md_http;
struct md_json;
struct md_pkey;
struct md_acme_acct;

typedef enum {
    MD_ACME_S_INIT,
    MD_ACME_S_ERROR,
    MD_ACME_S_LIVE,
} md_acme_state_t;

typedef struct md_acme md_acme;

struct md_acme {
    const char *url;
    apr_pool_t *pool;
    md_acme_state_t state;
    
    const char *new_authz;
    const char *new_cert;
    const char *new_reg;
    const char *revoke_cert;
    
    struct md_http *http;
    struct md_acme_acct *acct;
    
    const char *nonce;
};


apr_status_t md_acme_init(apr_pool_t *pool);

apr_status_t md_acme_create(md_acme **pacme, apr_pool_t *p, const char *url);

apr_status_t md_acme_setup(md_acme *acme);

apr_status_t md_acme_add_acct(md_acme *acme, struct md_acme_acct *acct);


typedef struct md_acme_req md_acme_req;

typedef apr_status_t md_acme_req_init_cb(md_acme_req *req, void *baton);

typedef void md_acme_req_success_cb(md_acme *acme, const char *location, 
                                    struct md_json *body, void *baton);

struct md_acme_req {
    md_acme *acme;
    apr_pool_t *pool;
    
    const char *url;
    apr_table_t *prot_hdrs;
    struct md_json *req_json;

    apr_table_t *resp_hdrs;
    struct md_json *resp_json;
    
    apr_status_t status;
    
    md_acme_req_init_cb *on_init;
    md_acme_req_success_cb *on_success;
    void *baton;
};

md_acme_req *md_acme_req_create(md_acme *acme, const char *url);
apr_status_t md_acme_req_send(md_acme_req *req);

#endif /* md_acme_h */
