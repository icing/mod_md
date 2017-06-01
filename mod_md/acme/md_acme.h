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
struct apr_hash_t;
struct md_http_t;
struct md_json_t;
struct md_pkey_t;
struct md_t;
struct md_acme_acct;
struct md_proto_t;


#define MD_PROTO_ACME       "ACME"


typedef enum {
    MD_ACME_S_UNKNOWN,              /* MD has not been analysed yet */
    MD_ACME_S_REGISTERED,           /* MD is registered at CA, but not more */
    MD_ACME_S_TOS_ACCEPTED,         /* Terms of Service were accepted by account holder */
    MD_ACME_S_CHALLENGED,           /* MD challenge information for all domains is known */
    MD_ACME_S_VALIDATED,            /* MD domains have been validated */
    MD_ACME_S_CERTIFIED,            /* MD has valid certificate */
    MD_ACME_S_DENIED,               /* MD domains (at least one) have been denied by CA */
} md_acme_state_t;

typedef struct md_acme_t md_acme_t;

struct md_acme_t {
    const char *url;
    apr_pool_t *pool;
    struct md_store_t *store;
    
    const char *new_authz;
    const char *new_cert;
    const char *new_reg;
    const char *revoke_cert;
    
    struct md_http_t *http;
    
    const char *nonce;
    unsigned int pkey_bits;
};

/**
 * Global init, call once at start up.
 */
apr_status_t md_acme_init(apr_pool_t *pool);

/**
 * Create a new ACME server instance. If path is not NULL, will use that directory
 * for persisting information. Will load any inforation persisted in earlier session.
 * url needs only be specified for instances where this has never been persisted before.
 *
 * @param pacme   will hold the ACME server instance on success
 * @param p       pool to used
 * @param url     url of the server, optional if known at path
 */
apr_status_t md_acme_create(md_acme_t **pacme, apr_pool_t *p, const char *url,
                            struct md_store_t *store);

/**
 * Contact the ACME server and retrieve its directory information.
 * 
 * @param acme    the ACME server to contact
 */
apr_status_t md_acme_setup(md_acme_t *acme);


/**
 * A request against an ACME server
 */
typedef struct md_acme_req_t md_acme_req_t;

/**
 * Request callback to initialize before sending. May be invoked more than once in
 * case of retries.
 */
typedef apr_status_t md_acme_req_init_cb(md_acme_req_t *req, void *baton);

/**
 * Request callback on a successfull response (HTTP response code 2xx).
 */
typedef apr_status_t md_acme_req_success_cb(md_acme_t *acme, const apr_table_t *headers, 
                                            struct md_json_t *body, void *baton);

struct md_acme_req_t {
    md_acme_t *acme;                 /* the ACME server to talk to */
    apr_pool_t *pool;              /* pool for the request duration */
    
    const char *url;               /* url to POST the request to */
    apr_table_t *prot_hdrs;        /* JWS headers needing protection (nonce) */
    struct md_json_t *req_json;      /* JSON to be POSTed in request body */

    apr_table_t *resp_hdrs;        /* HTTP response headers */
    struct md_json_t *resp_json;     /* JSON response body recevied */
    
    apr_status_t rv;               /* status of request */
    
    md_acme_req_init_cb *on_init;  /* callback to initialize the request before submit */
    md_acme_req_success_cb *on_success; /* callback on successful response */
    void *baton;                   /* userdata for callbacks */
};

/**
 * Perform a request against the ACME server for the given url.
 * 
 * @param acme        the ACME server to talk to
 * @param url         the url to send the request to
 * @param on_init     callback to initialize the request data
 * @param on_success  callback on successful response
 * @param baton       userdata for callbacks
 */
apr_status_t md_acme_req_do(md_acme_t *acme, const char *url,
                            md_acme_req_init_cb *on_init,
                            md_acme_req_success_cb *on_success,
                            void *baton);

apr_status_t md_acme_req_body_init(md_acme_req_t *req, struct md_json_t *jpayload, 
                                   struct md_pkey_t *key);

apr_status_t md_acme_protos_add(apr_hash_t *protos, apr_pool_t *p);

#endif /* md_acme_h */
