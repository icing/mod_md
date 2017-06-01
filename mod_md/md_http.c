/* Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
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

#include <curl/curl.h>

#include "md_http.h"
#include "md_log.h"

struct md_http_t {
    apr_pool_t *pool;
    apr_bucket_alloc_t *bucket_alloc;
    CURL *curl;
};


static int init_done;
static long next_req_id;

static apr_status_t http_pool_cleanup(void *data)
{
    md_http_t *http = data;
    if (http->curl) {
        curl_easy_cleanup(http->curl);
        http->curl = NULL;
    }
    return APR_SUCCESS;
}

static size_t req_data_cb(void *data, size_t len, size_t nmemb, void *baton)
{
    apr_bucket_brigade *body = baton;
    size_t blen, read_len = 0, max_len = len * nmemb;
    const char *bdata;
    apr_bucket *b;
    apr_status_t rv;
    
    while (body && !APR_BRIGADE_EMPTY(body) && max_len > 0) {
        b = APR_BRIGADE_FIRST(body);
        if (APR_BUCKET_IS_METADATA(b)) {
            if (APR_BUCKET_IS_EOS(b)) {
                body = NULL;
            }
        }
        else {
            rv = apr_bucket_read(b, &bdata, &blen, APR_BLOCK_READ);
            if (rv == APR_SUCCESS) {
                if (blen > max_len) {
                    apr_bucket_split(b, max_len);
                    blen = max_len;
                }
                memcpy(data, bdata, blen);
                read_len += blen;
                max_len -= blen;
            }
            else {
                body = NULL;
                if (!APR_STATUS_IS_EOF(rv)) {
                    /* everything beside EOF is an error */
                    read_len = CURL_READFUNC_ABORT;
                }
            }
            
        }
        apr_bucket_delete(b);
    }
    
    return read_len;
}

static size_t resp_data_cb(void *data, size_t len, size_t nmemb, void *baton)
{
    md_http_response_t *res = baton;
    size_t blen = len * nmemb;

    if (res->body) {
        apr_status_t rv = apr_brigade_write(res->body, NULL, NULL, (const char *)data, blen);
        if (rv != APR_SUCCESS) {
            /* returning anything != blen will make CURL fail this */
            return 0;
        }
    }
    return blen;
}

static size_t header_cb(void *buffer, size_t elen, size_t nmemb, void *baton)
{
    md_http_response_t *res = baton;
    size_t len, clen = elen * nmemb;
    const char *name = NULL, *value = "", *b = buffer;
    int i;
    
    len = (clen && b[clen-1] == '\n')? clen-1 : clen;
    len = (len && b[len-1] == '\r')? len-1 : len;
    for (i = 0; i < len; ++i) {
        if (b[i] == ':') {
            name = apr_pstrndup(res->req->pool, b, i);
            ++i;
            while (i < len && b[i] == ' ') {
                ++i;
            }
            if (i < len) {
                value = apr_pstrndup(res->req->pool, b+i, len - i);
            }
            break;
        }
    }
    
    if (name != NULL) {
        apr_table_add(res->headers, name, value);
    }
    return clen;
}

apr_status_t md_http_create(md_http_t **phttp, apr_pool_t *p)
{
    md_http_t *http;
    
    if (!init_done) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        init_done = 1;
    }
    
    http = apr_pcalloc(p, sizeof(*http));
    http->pool = p;
    http->bucket_alloc = apr_bucket_alloc_create(p);
    if (!http->bucket_alloc) {
        return APR_EGENERAL;
    }
    
    http->curl = curl_easy_init();
    if (!http->curl) {
        return APR_EGENERAL;
    }
    
    apr_pool_pre_cleanup_register(p, http, http_pool_cleanup);    
    *phttp = http;
    
    curl_easy_setopt(http->curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(http->curl, CURLOPT_HEADERDATA, NULL);
    curl_easy_setopt(http->curl, CURLOPT_READFUNCTION, req_data_cb);
    curl_easy_setopt(http->curl, CURLOPT_READDATA, NULL);
    curl_easy_setopt(http->curl, CURLOPT_WRITEFUNCTION, resp_data_cb);
    curl_easy_setopt(http->curl, CURLOPT_WRITEDATA, NULL);

    return APR_SUCCESS;
}

static apr_status_t req_create(md_http_request_t **preq, md_http_t *http, 
                               const char *method, const char *url, struct apr_table_t *headers,
                               md_http_cb *cb, void *baton)
{
    md_http_request_t *req;
    apr_pool_t *pool;
    apr_status_t rv;
    
    rv = apr_pool_create(&pool, http->pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    req = apr_pcalloc(pool, sizeof(*req));
    req->id = next_req_id++;
    req->pool = pool; 
    req->http = http;
    req->method = method;
    req->url = url;
    req->headers = headers? apr_table_copy(req->pool, headers) : apr_table_make(req->pool, 5);
    req->cb = cb;
    req->baton = baton;

    *preq = req;
    return rv;
}

static void req_destroy(md_http_request_t *req) 
{
   apr_pool_destroy(req->pool);
}

typedef struct {
    md_http_request_t *req;
    struct curl_slist *hdrs;
    apr_status_t rv;
} curlify_hdrs_ctx;

static int curlify_headers(void *baton, const char *key, const char *value)
{
    curlify_hdrs_ctx *ctx = baton;
    const char *s;
    
    if (strchr(key, '\r') || strchr(key, '\n')
        || strchr(value, '\r') || strchr(value, '\n')) {
        ctx->rv = APR_EINVAL;
        return 0;
    }
    s = apr_psprintf(ctx->req->pool, "%s: %s", key, value);
    ctx->hdrs = curl_slist_append(ctx->hdrs, s);
    return 1;
}

static apr_status_t perform(md_http_request_t *req)
{
    apr_status_t rv = APR_SUCCESS;
    CURL *curl = req->http->curl;
    md_http_response_t *res;
    struct curl_slist *req_hdrs = NULL;

    res = apr_pcalloc(req->pool, sizeof(*res));
    
    res->req = req;
    res->rv = APR_SUCCESS;
    res->status = 400;
    res->headers = apr_table_make(req->pool, 5);
    res->body = apr_brigade_create(req->pool, req->http->bucket_alloc);
    
    curl_easy_setopt(curl, CURLOPT_URL, req->url);
    if (!apr_strnatcasecmp("GET", req->method)) {
        /* nop */
    }
    else if (!apr_strnatcasecmp("HEAD", req->method)) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    }
    else if (!apr_strnatcasecmp("POST", req->method)) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
    }
    else {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method);
    }
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, res);
    curl_easy_setopt(curl, CURLOPT_READDATA, req->body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, res);
    
    if (!apr_is_empty_table(req->headers)) {
        curlify_hdrs_ctx ctx;
        
        ctx.req = req;
        ctx.hdrs = NULL;
        ctx.rv = APR_SUCCESS;
        apr_table_do(curlify_headers, &ctx, req->headers, NULL);
        req_hdrs = ctx.hdrs;
        if (ctx.rv == APR_SUCCESS) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_hdrs);
        }
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, req->pool, 
                  "request %ld --> %s %s", req->id, req->method, req->url);
    
    if (md_log_is_level(req->pool, MD_LOG_TRACE3)) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    
    res->rv = curl_easy_perform(curl);
    if (res->rv == CURLE_OK) {
        long l;
        res->rv = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &l);
        if (res->rv == CURLE_OK) {
            res->status = (int)l;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, req->pool, 
                      "request %ld <-- %d", req->id, res->status);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, req->pool, 
                      "request %ld failed: %s", req->id, curl_easy_strerror(res->rv));
        res->rv = APR_EGENERAL;
    }
    
    if (req->cb) {
        res->rv = req->cb(res);
    }
    
    rv = res->rv;
    req_destroy(req);
    if (req_hdrs) {
        curl_slist_free_all(req_hdrs);
    }
    
    return rv;
}

static apr_status_t schedule(md_http_request_t *req, 
                             apr_bucket_brigade *body, int detect_clen,
                             long *preq_id) 
{
    apr_status_t rv;
    
    req->body = body;
    req->body_len = body? -1 : 0;

    if (req->body && detect_clen) {
        rv = apr_brigade_length(req->body, 1, &req->body_len);
        if (rv != APR_SUCCESS) {
            req_destroy(req);
            return rv;
        }
    }
    
    if (req->body_len == 0 && apr_strnatcasecmp("GET", req->method)) {
        apr_table_setn(req->headers, "Content-Length", "0");
    }
    else if (req->body_len > 0) {
        apr_table_setn(req->headers, "Content-Length", apr_off_t_toa(req->pool, req->body_len));
    }
    
    if (preq_id) {
        *preq_id = req->id;
    }
    
    /* we send right away */
    rv = perform(req);
    
    return rv;
}

apr_status_t md_http_GET(struct md_http_t *http, 
                         const char *url, struct apr_table_t *headers,
                         md_http_cb *cb, void *baton, long *preq_id)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "GET", url, headers, cb, baton);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    return schedule(req, NULL, 0, preq_id);
}

apr_status_t md_http_HEAD(struct md_http_t *http, 
                          const char *url, struct apr_table_t *headers,
                          md_http_cb *cb, void *baton, long *preq_id)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "HEAD", url, headers, cb, baton);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    return schedule(req, NULL, 0, preq_id);
}

apr_status_t md_http_POST(struct md_http_t *http, const char *url, 
                          struct apr_table_t *headers, const char *content_type, 
                          apr_bucket_brigade *body,
                          md_http_cb *cb, void *baton, long *preq_id)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "POST", url, headers, cb, baton);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    if (content_type) {
        apr_table_set(req->headers, "Content-Type", content_type); 
    }
    return schedule(req, body, 1, preq_id);
}

apr_status_t md_http_POSTd(md_http_t *http, const char *url, 
                           struct apr_table_t *headers, const char *content_type, 
                           const char *data, size_t data_len, 
                           md_http_cb *cb, void *baton, long *preq_id)
{
    md_http_request_t *req;
    apr_status_t rv;
    apr_bucket_brigade *body = NULL;
    
    rv = req_create(&req, http, "POST", url, headers, cb, baton);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (data && data_len > 0) {
        body = apr_brigade_create(req->pool, req->http->bucket_alloc);
        rv = apr_brigade_write(body, NULL, NULL, data, data_len);
        if (rv != APR_SUCCESS) {
            req_destroy(req);
            return rv;
        }
    }
    
    if (content_type) {
        apr_table_set(req->headers, "Content-Type", content_type); 
    }
     
    return schedule(req, body, 1, preq_id);
}

apr_status_t md_http_await(md_http_t *http, long req_id)
{
    return APR_SUCCESS;
}
