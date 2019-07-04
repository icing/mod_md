/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_buckets.h>
#include <apr_hash.h>
#include <apr_time.h>
#include <apr_strings.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_log.h"
#include "md_http.h"
#include "md_store.h"
#include "md_util.h"
#include "md_ocsp.h"

#define MD_OTHER            "other"

#define MD_OCSP_ID_LENGTH   SHA_DIGEST_LENGTH
   
struct md_ocsp_reg_t {
    apr_pool_t *p;
    md_store_t *store;
    const char *user_agent;
    const char *proxy_url;
    apr_hash_t *hash;
};

typedef struct md_ocsp_status_t md_ocsp_status_t; 
struct md_ocsp_status_t {
    char id[MD_OCSP_ID_LENGTH];
    OCSP_CERTID *certid;
    const char *responder_url;
    md_timeperiod_t lifetime;
    md_data_t req_der;
    md_timeperiod_t resp_valid;
    md_data_t resp_der;
    
    OCSP_REQUEST *ocsp_req;
};

static apr_status_t init_cert_id(char *buffer, apr_size_t len, md_cert_t *cert)
{
    X509 *x = md_cert_get_X509(cert);
    
    assert(len == SHA_DIGEST_LENGTH);
    if (X509_digest(x, EVP_sha1(), (unsigned char*)buffer, NULL) != 1) {
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

static void ostat_req_cleanup(md_ocsp_status_t *ostat)
{
    if (ostat->ocsp_req) {
        OCSP_REQUEST_free(ostat->ocsp_req);
        ostat->ocsp_req = NULL;
    }
    if (ostat->req_der.data) {
        OPENSSL_free((void*)ostat->req_der.data);
        ostat->req_der.data = NULL;
        ostat->req_der.len = 0;
    }
}

static int ostat_cleanup(void *ctx, const void *key, apr_ssize_t klen, const void *val)
{
    md_ocsp_reg_t *reg = ctx;
    md_ocsp_status_t *ostat = (md_ocsp_status_t *)val;
    
    (void)reg;
    (void)key;
    (void)klen;
    ostat_req_cleanup(ostat);
    if (ostat->certid) {
        OCSP_CERTID_free(ostat->certid);
        ostat->certid = NULL;
    }
    if (ostat->resp_der.data) {
        OPENSSL_free((void*)ostat->resp_der.data);
        ostat->resp_der.data = NULL;
        ostat->resp_der.len = 0;
    }
    return 1;
}

static apr_status_t ocsp_reg_cleanup(void *data)
{
    md_ocsp_reg_t *reg = data;
    
    /* free all OpenSSL structures that we hold */
    apr_hash_do(ostat_cleanup, reg, reg->hash);
    return APR_SUCCESS;
}

apr_status_t md_ocsp_reg_make(md_ocsp_reg_t **preg, apr_pool_t *p, md_store_t *store, 
                              const char *user_agent, const char *proxy_url)
{
    md_ocsp_reg_t *reg;
    apr_status_t rv = APR_SUCCESS;
    
    reg = apr_palloc(p, sizeof(*reg));
    if (!reg) {
        rv = APR_ENOMEM;
        goto leave;
    }
    reg->p = p;
    reg->store = store;
    reg->user_agent = user_agent;
    reg->proxy_url = proxy_url;
    reg->hash = apr_hash_make(p);
    apr_pool_cleanup_register(p, reg, ocsp_reg_cleanup, apr_pool_cleanup_null);
leave:
    *preg = (APR_SUCCESS == rv)? reg : NULL;
    return rv;
}

apr_status_t md_ocsp_prime(md_ocsp_reg_t *reg, md_cert_t *cert, md_cert_t *issuer, const md_t *md)
{
    char id[MD_OCSP_ID_LENGTH];
    md_ocsp_status_t *ostat;
    STACK_OF(OPENSSL_STRING) *ssk = NULL;
    const char *name;
    apr_status_t rv;
    
    name = md? md->name : MD_OTHER;
    rv = init_cert_id(id, sizeof(id), cert);
    if (APR_SUCCESS != rv) goto leave;
    
    ostat = apr_hash_get(reg->hash, id, sizeof(id));
    if (ostat) goto leave; /* already seen it, cert is used in >1 server_rec */
    
    ostat = apr_pcalloc(reg->p, sizeof(*ostat));
    memcpy(ostat->id, id, sizeof(ostat->id));
    
    ssk = X509_get1_ocsp(md_cert_get_X509(cert));
    if (!ssk) {
        rv = APR_EGENERAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, reg->p, 
                      "md[%s]: certificate with serial %s has not OCSP responder URL", 
                      name, md_cert_get_serial_number(cert, reg->p));
        goto leave;
    }
    ostat->responder_url = apr_pstrdup(reg->p, sk_OPENSSL_STRING_value(ssk, 0));
    X509_email_free(ssk);

    ostat->certid = OCSP_cert_to_id(NULL, md_cert_get_X509(cert), md_cert_get_X509(issuer));
    if (!ostat->certid) {
        rv = APR_EGENERAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, reg->p, 
                      "md[%s]: unable to create OCSP certid for certificate with serial %s", 
                      name, md_cert_get_serial_number(cert, reg->p));
        goto leave;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, reg->p, 
                  "md[%s]: adding ocsp info (responder=%s)", 
                  name, ostat->responder_url);
    apr_hash_set(reg->hash, ostat->id, sizeof(ostat->id), ostat);
    rv = APR_SUCCESS;
leave:
    return rv;
}

apr_status_t md_ocsp_get_status(unsigned char **pder, int *pderlen,
                                md_ocsp_reg_t *reg, md_cert_t *cert,
                                apr_pool_t *p, const md_t *md)
{
    char id[MD_OCSP_ID_LENGTH];
    md_ocsp_status_t *ostat;
    const char *name;
    apr_status_t rv;
    
    (void)p;
    (void)md;
    name = md? md->name : MD_OTHER;
    rv = init_cert_id(id, sizeof(id), cert);
    if (APR_SUCCESS != rv) goto leave;
    
    ostat = apr_hash_get(reg->hash, id, sizeof(id));
    if (!ostat) {
        rv = APR_ENOENT;
        goto leave;
    }
    
    *pder = NULL;
    *pderlen = 0;
    if (ostat->resp_der.len <= 0) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, reg->p, 
                      "md[%s]: no OCSP response available", name);
        goto leave;
    }

    *pder = OPENSSL_malloc(ostat->resp_der.len);
    if (*pder == NULL) {
        rv = APR_ENOMEM;
        goto leave;
    }
    memcpy(*pder, ostat->resp_der.data, ostat->resp_der.len);
    *pderlen = (int)ostat->resp_der.len;
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, reg->p, 
                  "md[%s]: returning %ld bytes of OCSP response", 
                  name, (long)ostat->resp_der.len);
leave:
    return rv;
}

apr_size_t md_ocsp_count(md_ocsp_reg_t *reg)
{
    return apr_hash_count(reg->hash);
}

typedef struct {
    apr_array_header_t *todos;
    const md_timeslice_t *window;
    apr_time_t next_run;
    
    int max_parallel;
} md_ocsp_todo_ctx_t;


static int select_todos(void *baton, const void *key, apr_ssize_t klen, const void *val)
{
    md_ocsp_todo_ctx_t *ctx = baton;
    md_ocsp_status_t *ostat = (md_ocsp_status_t *)val;
    md_timeperiod_t renewal;
    (void)key;
    (void)klen;
    if (ostat->resp_der.len == 0 || ostat->lifetime.end == 0) {
        APR_ARRAY_PUSH(ctx->todos, md_ocsp_status_t*) = ostat;
        goto leave;
    }
    renewal = md_timeperiod_slice_before_end(&ostat->lifetime, ctx->window);
    if (md_timeperiod_has_started(&renewal, apr_time_now())) {
        APR_ARRAY_PUSH(ctx->todos, md_ocsp_status_t*) = ostat;
        goto leave;
    }
    if (renewal.start < ctx->next_run) {
        ctx->next_run = renewal.start;
    }
leave:
    return 1;
}

static apr_status_t ostat_on_req_status(const md_http_request_t *req, apr_status_t status, 
                                        void *baton)
{
    md_ocsp_status_t *ostat = baton;

    if (APR_SUCCESS != status) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, status, req->pool, 
                      "req[%d]: status failed",  req->id);
    }
    ostat_req_cleanup(ostat);
    return APR_SUCCESS;
}

static apr_status_t ostat_on_resp(const md_http_response_t *resp, void *baton)
{
    md_ocsp_status_t *ostat = baton;
    md_http_request_t *req = resp->req;
    OCSP_RESPONSE *ocsp_resp = NULL;
    OCSP_BASICRESP *basic_resp = NULL;
    char *der;
    apr_size_t der_len;
    apr_status_t rv = APR_SUCCESS;
    int n, breason, bstatus;
    ASN1_GENERALIZEDTIME *bup = NULL, *bnextup = NULL;
    md_data_t new_der;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, req->pool, 
                  "req[%d]: OCSP respoonse: %d, cl=%s, ct=%s",  req->id, resp->status,
                  apr_table_get(resp->headers, "Content-Length"),
                  apr_table_get(resp->headers, "Content-Type"));
    if (APR_SUCCESS == (rv = apr_brigade_pflatten(resp->body, &der, &der_len, req->pool))) {
        const unsigned char *bf = (const unsigned char*)der;
        
        if (NULL == (ocsp_resp = d2i_OCSP_RESPONSE(NULL, &bf, (long)der_len))) {
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                          "req[%d]: response body does not parse as OCSP response", req->id);
            goto leave;
        }
        /* got a response! but what does it say? */
        n = OCSP_response_status(ocsp_resp);
        if (OCSP_RESPONSE_STATUS_SUCCESSFUL != n) {
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                          "req[%d]: OCSP response not successful: %d", req->id, n);
            goto leave;
        }
        basic_resp = OCSP_response_get1_basic(ocsp_resp);
        if (!basic_resp) {
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                          "req[%d]: OCSP response has no basicresponse", req->id);
            goto leave;
        }
        n = OCSP_resp_find_status(basic_resp, ostat->certid, &bstatus,
                                   &breason, NULL, &bup, &bnextup);
        if (n != 1) {
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                          "req[%d]: OCSP basicresponse, unable to find status", req->id);
            goto leave;
        }
        if (V_OCSP_CERTSTATUS_UNKNOWN == bstatus) {
            rv = APR_ENOENT;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                          "req[%d]: OCSP basicresponse says cert is unknown", req->id);
            goto leave;
        }
        if (!bnextup) {
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                          "req[%d]: OCSP basicresponse validity unknown", req->id);
            goto leave;
        }
        
        new_der.data = NULL;
        new_der.len = 0;
        n = i2d_OCSP_RESPONSE(ocsp_resp, (unsigned char**)&new_der.data);
        if (n <= 0) {
            rv = APR_EGENERAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                          "req[%d]: error DER encoding OCSP response", req->id);
            goto leave;
        }
        new_der.len = (apr_size_t)n;
        
        ostat->resp_valid.start = bup? md_asn1_generalized_time_get(bup) : apr_time_now();
        ostat->resp_valid.end = md_asn1_generalized_time_get(bnextup);
        if (ostat->resp_der.data) {
            OPENSSL_free((void*)ostat->resp_der.data);
            ostat->resp_der.data = NULL;
            ostat->resp_der.len = 0;
        }
        ostat->resp_der = new_der;
        
        /* Coming here, we have a response for our certid and it is either GOOD
         * or REVOKED. Both cases we want to remember and use in stapling. */
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                      "req[%d]: cert status is %s, answer valid [%s], OCSP repsone DER length %ld", 
                      req->id, (bstatus == V_OCSP_CERTSTATUS_GOOD)? "GOOD" : "REVOKED",
                      md_timeperiod_print(req->pool, &ostat->resp_valid), 
                      (long)ostat->resp_der.len);
        
        rv = APR_SUCCESS;
    }

    (void)ostat;
leave:
    if (basic_resp) OCSP_BASICRESP_free(basic_resp);
    if (ocsp_resp) OCSP_RESPONSE_free(ocsp_resp);
    return rv;
}


static apr_status_t next_todo(md_http_request_t **preq, void *baton, 
                              md_http_t *http, int in_flight)
{
    md_ocsp_todo_ctx_t *ctx = baton;
    md_ocsp_status_t *ostat, **postat;    
    OCSP_CERTID *certid = NULL;
    md_http_request_t *req = NULL;
    apr_status_t rv = APR_ENOENT;
    int len;
    
    if (in_flight < ctx->max_parallel) {
        postat = apr_array_pop(ctx->todos);
        if (postat) {
            ostat = *postat;
            if (!ostat->ocsp_req) {
                ostat->ocsp_req = OCSP_REQUEST_new();
                if (!ostat->ocsp_req) goto leave;
                certid = OCSP_CERTID_dup(ostat->certid);
                if (!certid) goto leave;
                if (!OCSP_request_add0_id(ostat->ocsp_req, certid)) goto leave;
                certid = NULL;
            }
            if (0 == ostat->req_der.len) {
                len = i2d_OCSP_REQUEST(ostat->ocsp_req, (unsigned char**)&ostat->req_der.data);
                if (len < 0) goto leave;
                ostat->req_der.len = (apr_size_t)len;
            }
            rv = md_http_POSTd_create(&req, http, ostat->responder_url, NULL, 
                                      "application/ocsp-request", &ostat->req_der);
            if (APR_SUCCESS != rv) goto leave;
            md_http_set_on_status_cb(req, ostat_on_req_status, ostat);
            md_http_set_on_response_cb(req, ostat_on_resp, ostat);
            rv = APR_SUCCESS;
        }
    }
leave:
    *preq = (APR_SUCCESS == rv)? req : NULL;
    if (certid) OCSP_CERTID_free(certid);
    return rv;
}


void md_ocsp_renew(md_ocsp_reg_t *reg, const md_timeslice_t *window, 
                   apr_pool_t *p, apr_pool_t *ptemp, apr_time_t *pnext_run)
{
    md_ocsp_todo_ctx_t ctx;
    md_http_t *http;
    apr_status_t rv = APR_SUCCESS;
    
    (void)p;
    (void)pnext_run;
    
    ctx.todos = apr_array_make(ptemp, (int)md_ocsp_count(reg), sizeof(md_ocsp_status_t*));
    ctx.window = window;
    ctx.next_run = *pnext_run;
    ctx.max_parallel = 6; /* the magic number in HTTP */
    
    apr_hash_do(select_todos, &ctx, reg->hash);
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                  "certificates that need a OCSP status update now: %d",  ctx.todos->nelts);
    if (!ctx.todos->nelts) goto leave;
    
    rv = md_http_create(&http, ptemp, reg->user_agent, reg->proxy_url);
    if (APR_SUCCESS != rv) goto leave;
    
    rv = md_http_multi_perform(http, next_todo, &ctx);
    
leave:
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "ocsp_renew done");
    }
    return;
}
