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

#ifndef mod_md_md_http_h
#define mod_md_md_http_h

struct apr_table_t;
struct apr_bucket_brigade;

typedef struct md_http_t md_http_t;

typedef struct md_http_request_t md_http_request_t;
typedef struct md_http_response_t md_http_response_t;

typedef apr_status_t md_http_cb(const md_http_response_t *res);

struct md_http_request_t {
    long id;
    md_http_t *http;
    apr_pool_t *pool;
    const char *method;
    const char *url;
    apr_table_t *headers;
    struct apr_bucket_brigade *body;
    apr_off_t body_len;
    apr_off_t resp_limit;
    md_http_cb *cb;
    void *baton;
    void *internals;
};

struct md_http_response_t {
    md_http_request_t *req;
    apr_status_t rv;
    int status;
    apr_table_t *headers;
    struct apr_bucket_brigade *body;
};

apr_status_t md_http_create(md_http_t **phttp, apr_pool_t *p);

void md_http_set_response_limit(md_http_t *http, apr_off_t resp_limit);

apr_status_t md_http_GET(md_http_t *http, 
                         const char *url, struct apr_table_t *headers,
                         md_http_cb *cb, void *baton, long *preq_id);

apr_status_t md_http_HEAD(md_http_t *http, 
                          const char *url, struct apr_table_t *headers,
                          md_http_cb *cb, void *baton, long *preq_id);

apr_status_t md_http_POST(md_http_t *http, const char *url, 
                          struct apr_table_t *headers, const char *content_type, 
                          struct apr_bucket_brigade *body,
                          md_http_cb *cb, void *baton, long *preq_id);

apr_status_t md_http_POSTd(md_http_t *http, const char *url, 
                           struct apr_table_t *headers, const char *content_type, 
                           const char *data, size_t data_len, 
                           md_http_cb *cb, void *baton, long *preq_id);

apr_status_t md_http_await(md_http_t *http, long req_id);



#endif /* md_http_h */
