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
#include <apr_date.h>
#include <apr_strings.h>
#include <apr_thread_mutex.h>

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
#include "md_json.h"
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
    apr_thread_mutex_t *mutex;
    md_timeslice_t renew_window;
};

typedef struct md_ocsp_status_t md_ocsp_status_t; 
struct md_ocsp_status_t {
    md_data_t id;
    OCSP_CERTID *certid;
    const char *responder_url;
    
    apr_time_t next_retrieve; /* when the responder shall be asked again */
    int errors;               /* consecutive failed attempts */

    md_data_t resp_der;
    md_timeperiod_t resp_valid;
    
    md_data_t req_der;
    OCSP_REQUEST *ocsp_req;
    md_ocsp_reg_t *reg;

    const char *md_name;
    const char *file_name;
    
    apr_time_t resp_mtime;
    apr_time_t resp_last_check;
    
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

static apr_time_t ostat_get_renew_start(md_ocsp_status_t *ostat)
{
    md_timeperiod_t renewal;
    
    renewal = md_timeperiod_slice_before_end(&ostat->resp_valid, &ostat->reg->renew_window);
    return renewal.start;
} 

static int ostat_should_renew(md_ocsp_status_t *ostat) 
{
    md_timeperiod_t renewal;
    
    renewal = md_timeperiod_slice_before_end(&ostat->resp_valid, &ostat->reg->renew_window);
    return md_timeperiod_has_started(&renewal, apr_time_now());
}  

static apr_status_t ostat_set(md_ocsp_status_t *ostat, md_data_t *der, 
                              md_timeperiod_t *valid, apr_time_t mtime)
{
    apr_status_t rv = APR_SUCCESS;
    char *s = (char*)der->data;
    
    if (der->len) {
        s = OPENSSL_malloc(der->len);
        if (!s) {
            rv = APR_ENOMEM;
            goto leave;
        }
        memcpy((char*)s, der->data, der->len);
    }
 
    if (ostat->resp_der.data) {
        OPENSSL_free((void*)ostat->resp_der.data);
        ostat->resp_der.data = NULL;
        ostat->resp_der.len = 0;
    }
    
    ostat->resp_der.data = s;
    ostat->resp_der.len = der->len;
    ostat->resp_valid = *valid;
    ostat->resp_mtime = mtime;
    
    ostat->errors = 0;
    ostat->next_retrieve = ostat_get_renew_start(ostat);
    
leave:
    return rv;
}

static apr_status_t ostat_from_json(md_data_t *resp_der, md_timeperiod_t *resp_valid, 
                                    md_json_t *json, apr_pool_t *p)
{
    const char *s;
    md_timeperiod_t valid;
    apr_status_t rv = APR_ENOENT;
    
    memset(resp_der, 0, sizeof(*resp_der));
    memset(resp_valid, 0, sizeof(*resp_valid));
    s = md_json_dups(p, json, MD_KEY_VALID_FROM, NULL);
    if (s && *s) valid.start = apr_date_parse_rfc(s);
    s = md_json_dups(p, json, MD_KEY_VALID_UNTIL, NULL);
    if (s && *s) valid.end = apr_date_parse_rfc(s);
    s = md_json_dups(p, json, MD_KEY_RESPONSE, NULL);
    if (!s || !*s) goto leave;

    md_util_base64url_decode(resp_der, s, p);
    *resp_valid = valid;
    rv = APR_SUCCESS;
leave:
    return rv;
}

static void ostat_to_json(md_json_t *json, const md_data_t *resp_der, 
                          const md_timeperiod_t *resp_valid, apr_pool_t *p)
{
    char ts[APR_RFC822_DATE_LEN];

    if (resp_der->len > 0) {
        md_json_sets(md_util_base64url_encode(resp_der, p), json, MD_KEY_RESPONSE, NULL);
        
        if (resp_valid->start > 0) {
            apr_rfc822_date(ts, resp_valid->start);
            md_json_sets(ts, json, MD_KEY_VALID_FROM, NULL);
        }
        if (resp_valid->end > 0) {
            apr_rfc822_date(ts, resp_valid->end);
            md_json_sets(ts, json, MD_KEY_VALID_UNTIL, NULL);
        }
    }
}

static apr_status_t ocsp_status_refresh(md_ocsp_status_t *ostat, apr_pool_t *ptemp)
{
    md_store_t *store = ostat->reg->store;
    md_json_t *jprops;
    apr_time_t mtime;
    apr_status_t rv = APR_EAGAIN;
    md_data_t resp_der;
    md_timeperiod_t resp_valid;
    
    mtime = md_store_get_modified(store, MD_SG_OCSP, ostat->md_name, ostat->file_name, ptemp);
    if (mtime <= ostat->resp_mtime) goto leave;
    rv = md_store_load_json(store, MD_SG_OCSP, ostat->md_name, ostat->file_name, &jprops, ptemp);
    if (APR_SUCCESS != rv) goto leave;
    rv = ostat_from_json(&resp_der, &resp_valid, jprops, ptemp);
    if (APR_SUCCESS != rv) goto leave;
    rv = ostat_set(ostat, &resp_der, &resp_valid, mtime);
    if (APR_SUCCESS != rv) goto leave;
leave:
    return rv;
}


static apr_status_t ocsp_status_save(const md_data_t *resp_der, const md_timeperiod_t *resp_valid,
                                     md_ocsp_status_t *ostat, apr_pool_t *ptemp)
{
    md_store_t *store = ostat->reg->store;
    md_json_t *jprops;
    apr_time_t mtime;
    apr_status_t rv;
    
    jprops = md_json_create(ptemp);
    ostat_to_json(jprops, resp_der, resp_valid, ptemp);
    rv = md_store_save_json(store, ptemp, MD_SG_OCSP, ostat->md_name, ostat->file_name, jprops, 0);
    if (APR_SUCCESS != rv) goto leave;
    mtime = md_store_get_modified(store, MD_SG_OCSP, ostat->md_name, ostat->file_name, ptemp);
    if (mtime) ostat->resp_mtime = mtime;
leave:
    return rv;
}

static apr_status_t ocsp_reg_cleanup(void *data)
{
    md_ocsp_reg_t *reg = data;
    
    /* free all OpenSSL structures that we hold */
    apr_hash_do(ostat_cleanup, reg, reg->hash);
    return APR_SUCCESS;
}

apr_status_t md_ocsp_reg_make(md_ocsp_reg_t **preg, apr_pool_t *p, md_store_t *store, 
                              const md_timeslice_t *renew_window,
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
    reg->renew_window = *renew_window;
    
    rv = apr_thread_mutex_create(&reg->mutex, APR_THREAD_MUTEX_NESTED, p);
    if (APR_SUCCESS != rv) goto leave;

    apr_pool_cleanup_register(p, reg, ocsp_reg_cleanup, apr_pool_cleanup_null);
leave:
    *preg = (APR_SUCCESS == rv)? reg : NULL;
    return rv;
}

apr_status_t md_ocsp_prime(md_ocsp_reg_t *reg, md_cert_t *cert, md_cert_t *issuer, const md_t *md)
{
    char iddata[MD_OCSP_ID_LENGTH];
    md_ocsp_status_t *ostat;
    STACK_OF(OPENSSL_STRING) *ssk = NULL;
    const char *name;
    md_data_t id;
    apr_status_t rv;
    
    /* Called during post_config. no mutex protection needed */
    name = md? md->name : MD_OTHER;
    id.data = iddata; id.len = sizeof(iddata);
    
    rv = init_cert_id((char*)id.data, id.len, cert);
    if (APR_SUCCESS != rv) goto leave;
    
    ostat = apr_hash_get(reg->hash, id.data, (apr_ssize_t)id.len);
    if (ostat) goto leave; /* already seen it, cert is used in >1 server_rec */
    
    ostat = apr_pcalloc(reg->p, sizeof(*ostat));
    md_data_assign_pcopy(&ostat->id, &id, reg->p);
    ostat->reg = reg;
    ostat->md_name = name;
    ostat->file_name = apr_psprintf(reg->p, "ocsp-%s.json", 
                                    md_util_base64url_encode(&id, reg->p));
    
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
    
    /* See, if we have something in store */
    ocsp_status_refresh(ostat, reg->p);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, reg->p, 
                  "md[%s]: adding ocsp info (responder=%s)", 
                  name, ostat->responder_url);
    apr_hash_set(reg->hash, ostat->id.data, (apr_ssize_t)ostat->id.len, ostat);
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
    apr_status_t rv, rv2;
    int locked = 0;
    
    (void)p;
    (void)md;
    name = md? md->name : MD_OTHER;
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, reg->p, 
                  "md[%s]: OCSP, get_status", name);
    rv = init_cert_id(id, sizeof(id), cert);
    if (APR_SUCCESS != rv) goto leave;
    
    ostat = apr_hash_get(reg->hash, id, sizeof(id));
    if (!ostat) {
        rv = APR_ENOENT;
        goto leave;
    }
    
    /* While the ostat instance itself always exists, the response data it holds
     * may vary over time and we need locked access to make a copy. */
    apr_thread_mutex_lock(reg->mutex);
    locked = 1;
    
    *pder = NULL;
    *pderlen = 0;
    if (ostat->resp_der.len <= 0) {
        /* No resonse known, check the store if out watchdog retrieved one 
         * in the meantime. */
        
        rv2 = ocsp_status_refresh(ostat, p);
        if (ostat->resp_der.len <= 0) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, reg->p, 
                          "md[%s]: OCSP, no response available", name);
            goto leave;
        }
    }
    /* We have a response */
    if (ostat_should_renew(ostat)) {
        /* But it is up for renewal. A watchdog should be busy with
         * retrieving a new one. In case of outages, this might take
         * a while, however. Pace the frequency of checks with the
         * urgency of a new response based on the remaining time. */
        long secs = apr_time_sec(md_timeperiod_remaining(&ostat->resp_valid, apr_time_now()));
        apr_time_t waiting_time; 
        
        /* every hour, every minute, every second */
        waiting_time = ((secs >= MD_SECS_PER_DAY)?
                        apr_time_from_sec(60 * 60) : ((secs >= 60)? 
                        apr_time_from_sec(60) : apr_time_from_sec(1)));
        if ((apr_time_now() - ostat->resp_last_check) >= waiting_time) {
            ostat->resp_last_check = apr_time_now();
            ocsp_status_refresh(ostat, p);
        }
    }
    
    *pder = OPENSSL_malloc(ostat->resp_der.len);
    if (*pder == NULL) {
        rv = APR_ENOMEM;
        goto leave;
    }
    memcpy(*pder, ostat->resp_der.data, ostat->resp_der.len);
    *pderlen = (int)ostat->resp_der.len;
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, reg->p, 
                  "md[%s]: OCSP, returning %ld bytes of response", 
                  name, (long)ostat->resp_der.len);
leave:
    if (locked) apr_thread_mutex_unlock(reg->mutex);
    return rv;
}

apr_size_t md_ocsp_count(md_ocsp_reg_t *reg)
{
    return apr_hash_count(reg->hash);
}

typedef struct {
    md_ocsp_reg_t *reg;
    apr_array_header_t *todos;
    apr_time_t next_run;
    
    int max_parallel;
} md_ocsp_todo_ctx_t;


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
    md_timeperiod_t valid;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, req->pool, 
                  "req[%d]: OCSP respoonse: %d, cl=%s, ct=%s",  req->id, resp->status,
                  apr_table_get(resp->headers, "Content-Length"),
                  apr_table_get(resp->headers, "Content-Type"));
    new_der.data = NULL;
    new_der.len = 0;
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
        
        /* Coming here, we have a response for our certid and it is either GOOD
         * or REVOKED. Both cases we want to remember and use in stapling. */
        
        n = i2d_OCSP_RESPONSE(ocsp_resp, (unsigned char**)&new_der.data);
        if (n <= 0) {
            rv = APR_EGENERAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                          "req[%d]: error DER encoding OCSP response", req->id);
            goto leave;
        }
        new_der.len = (apr_size_t)n;
        valid.start = bup? md_asn1_generalized_time_get(bup) : apr_time_now();
        valid.end = md_asn1_generalized_time_get(bnextup);

        /* First, update the instance with a copy */
        apr_thread_mutex_lock(ostat->reg->mutex);
        ostat_set(ostat, &new_der, &valid, apr_time_now());
        apr_thread_mutex_unlock(ostat->reg->mutex);
        
        /* Next, save the original response */
        rv = ocsp_status_save(&new_der, &valid, ostat, req->pool); 
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, req->pool, 
                          "md[%s]: error saving OCSP status", ostat->md_name);
            goto leave;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                      "req[%d]: cert status is %s, answer valid [%s], OCSP repsone DER length %ld", 
                      req->id, (bstatus == V_OCSP_CERTSTATUS_GOOD)? "GOOD" : "REVOKED",
                      md_timeperiod_print(req->pool, &ostat->resp_valid), 
                      (long)ostat->resp_der.len);
    }

leave:
    if (new_der.data) OPENSSL_free((void*)new_der.data);
    if (basic_resp) OCSP_BASICRESP_free(basic_resp);
    if (ocsp_resp) OCSP_RESPONSE_free(ocsp_resp);
    return rv;
}

static apr_status_t ostat_on_req_status(const md_http_request_t *req, apr_status_t status, 
                                        void *baton)
{
    md_ocsp_status_t *ostat = baton;

    if (APR_SUCCESS != status) {
        ++ostat->errors;
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, status, req->pool, 
                      "md[%s]: OCSP status update failed (%d. time)",  
                      ostat->md_name, ostat->errors);
    }
    ostat_req_cleanup(ostat);
    return APR_SUCCESS;
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

static int select_todos(void *baton, const void *key, apr_ssize_t klen, const void *val)
{
    md_ocsp_todo_ctx_t *ctx = baton;
    md_ocsp_status_t *ostat = (md_ocsp_status_t *)val;
    
    (void)key;
    (void)klen;
    if (ostat->next_retrieve <= apr_time_now()) {
        APR_ARRAY_PUSH(ctx->todos, md_ocsp_status_t*) = ostat;
    }
    return 1;
}

static int select_next_run(void *baton, const void *key, apr_ssize_t klen, const void *val)
{
    md_ocsp_todo_ctx_t *ctx = baton;
    md_ocsp_status_t *ostat = (md_ocsp_status_t *)val;
    apr_time_t now;
    
    (void)key;
    (void)klen;
    /* when does this need to retrieve again? */
    now = apr_time_now();
    ostat->next_retrieve = ostat_get_renew_start(ostat);
    if (ostat->next_retrieve < now) {
        ostat->next_retrieve = now + apr_time_from_sec(1);
        if (ostat->errors > 0){
            ostat->next_retrieve += apr_time_from_sec(1 << (ostat->errors > 10? 10 : ostat->errors));
        }
    }
    if (ostat->next_retrieve < ctx->next_run) {
        ctx->next_run = ostat->next_retrieve;
    }
    return 1;
}

void md_ocsp_renew(md_ocsp_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, apr_time_t *pnext_run)
{
    md_ocsp_todo_ctx_t ctx;
    md_http_t *http;
    apr_status_t rv = APR_SUCCESS;
    
    (void)p;
    (void)pnext_run;
    
    ctx.reg = reg;
    ctx.todos = apr_array_make(ptemp, (int)md_ocsp_count(reg), sizeof(md_ocsp_status_t*));
    ctx.next_run = *pnext_run;
    ctx.max_parallel = 6; /* the magic number in HTTP */
    
    apr_hash_do(select_todos, &ctx, reg->hash);
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                  "certificates that need a OCSP status update now: %d",  ctx.todos->nelts);
    if (!ctx.todos->nelts) goto leave;
    
    rv = md_http_create(&http, ptemp, reg->user_agent, reg->proxy_url);
    if (APR_SUCCESS != rv) goto leave;
    
    rv = md_http_multi_perform(http, next_todo, &ctx);

    apr_hash_do(select_next_run, &ctx, reg->hash);
    *pnext_run = ctx.next_run;
    
leave:
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "ocsp_renew done");
    }
    return;
}
