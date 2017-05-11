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

typedef struct md_http md_http;

typedef struct md_http_request md_http_request;
typedef struct md_http_response md_http_response;

typedef apr_status_t md_http_cb(const md_http_response *res);

struct md_http_request {
    long id;
    md_http *http;
    apr_pool_t *pool;
    const char *method;
    const char *url;
    apr_table_t *headers;
    apr_bucket_brigade *body;
    apr_off_t body_len;
    md_http_cb *cb;
    void *baton;
};

struct md_http_response {
    md_http_request *req;
    apr_status_t rv;
    int status;
    apr_table_t *headers;
    apr_bucket_brigade *body;
};

apr_status_t md_http_create(md_http **phttp, apr_pool_t *p);

apr_status_t md_http_GET(md_http *http, 
                         const char *url, struct apr_table_t *headers,
                         md_http_cb *cb, void *baton, long *preq_id);

apr_status_t md_http_POST(md_http *http, 
                          const char *url, struct apr_table_t *headers,
                          apr_bucket_brigade *body,
                          md_http_cb *cb, void *baton, long *preq_id);

apr_status_t md_http_POSTd(md_http *http, 
                           const char *url, struct apr_table_t *headers,
                           const char *data, size_t data_len, 
                           md_http_cb *cb, void *baton, long *preq_id);

apr_status_t md_http_await(md_http *http, long req_id);



#endif /* md_http_h */
