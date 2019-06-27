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

#ifndef mod_md_md_http_h
#define mod_md_md_http_h

struct apr_table_t;
struct apr_bucket_brigade;
struct apr_bucket_alloc_t;
struct md_data;

typedef struct md_http_t md_http_t;

typedef struct md_http_request_t md_http_request_t;
typedef struct md_http_response_t md_http_response_t;

/**
 * Callback invoked once per request, either when an error was encountered
 * or when everything succeeded and the request is about to be released. Only
 * in the last case will the status be APR_SUCCESS.
 */
typedef apr_status_t md_http_status_cb(const md_http_request_t *req, apr_status_t status, void *data);

/**
 * Callback invoked when the complete response has been received.
 */
typedef apr_status_t md_http_response_cb(const md_http_response_t *res, void *data);

typedef struct md_http_callbacks_t md_http_callbacks_t;
struct md_http_callbacks_t {
    md_http_status_cb *on_status;
    void *on_status_data;
    md_http_response_cb *on_response;
    void *on_response_data;
};

struct md_http_request_t {
    md_http_t *http;
    apr_pool_t *pool;
    struct apr_bucket_alloc_t *bucket_alloc;
    const char *method;
    const char *url;
    const char *user_agent;
    const char *proxy_url;
    apr_table_t *headers;
    struct apr_bucket_brigade *body;
    apr_off_t body_len;
    apr_off_t resp_limit;
    md_http_callbacks_t *cb;
    void *internals;
};

struct md_http_response_t {
    md_http_request_t *req;
    int status;
    apr_table_t *headers;
    struct apr_bucket_brigade *body;
};

apr_status_t md_http_create(md_http_t **phttp, apr_pool_t *p, const char *user_agent,
                            const char *proxy_url);

void md_http_set_response_limit(md_http_t *http, apr_off_t resp_limit);

/**
 * Perform the request. Then this function returns, the request and
 * all its memory has been freed and must no longer be used.
 */
apr_status_t md_http_perform(md_http_request_t *request);

apr_status_t md_http_multi_perform(apr_array_header_t *requests);

/**
 * Set the callback to be invoked once the status of a request is known.
 * @param req       the request
 * @param cb        the callback to invoke on the response
 * @param baton     data passed to the callback    
 */
void md_http_set_on_status_cb(md_http_request_t *req, md_http_status_cb *cb, void *baton);

/**
 * Set the callback to be invoked when the complete 
 * response has been successfully received. The HTTP status may
 * be 500, however.
 * @param req       the request
 * @param cb        the callback to invoke on the response
 * @param baton     data passed to the callback    
 */
void md_http_set_on_response_cb(md_http_request_t *req, md_http_response_cb *cb, void *baton);

/**
 * Create a GET reqest.
 * @param preq      the created request after success
 * @param http      the md_http instance 
 * @param url       the url to GET
 * @param headers   request headers
 */
apr_status_t md_http_GET_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                struct apr_table_t *headers);

/**
 * Create a HEAD reqest.
 * @param preq      the created request after success
 * @param http      the md_http instance 
 * @param url       the url to GET
 * @param headers   request headers
 */
apr_status_t md_http_HEAD_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                 struct apr_table_t *headers);

/**
 * Create a POST reqest with a bucket brigade as request body.
 * @param preq      the created request after success
 * @param http      the md_http instance 
 * @param url       the url to GET
 * @param headers   request headers
 * @param content_type the content_type of the body or NULL
 * @param body      the body of the request or NULL
 * @param detect_len scan the body to detect its length
 */
apr_status_t md_http_POST_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                 struct apr_table_t *headers, const char *content_type, 
                                 struct apr_bucket_brigade *body, int detect_len);

/**
 * Create a POST reqest with known request body data.
 * @param preq      the created request after success
 * @param http      the md_http instance 
 * @param url       the url to GET
 * @param headers   request headers
 * @param content_type the content_type of the body or NULL
 * @param body      the body of the request or NULL
 */
apr_status_t md_http_POSTd_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                  struct apr_table_t *headers, const char *content_type, 
                                  const struct md_data *body);

/*
 * Convenience functions for create+perform.
 */
apr_status_t md_http_GET_perform(md_http_t *http, const char *url, 
                                 struct apr_table_t *headers,
                                 md_http_response_cb *cb, void *baton);
apr_status_t md_http_HEAD_perform(md_http_t *http, const char *url, 
                                  struct apr_table_t *headers,
                                  md_http_response_cb *cb, void *baton);
apr_status_t md_http_POST_perform(md_http_t *http, const char *url, 
                                  struct apr_table_t *headers, const char *content_type, 
                                  struct apr_bucket_brigade *body, int detect_len, 
                                  md_http_response_cb *cb, void *baton);
apr_status_t md_http_POSTd_perform(md_http_t *http, const char *url, 
                                   struct apr_table_t *headers, const char *content_type, 
                                   const struct md_data *body, 
                                   md_http_response_cb *cb, void *baton);

void md_http_req_destroy(md_http_request_t *req);

/**************************************************************************************************/
/* interface to implementation */

typedef apr_status_t md_http_init_cb(void);
typedef void md_http_req_cleanup_cb(md_http_request_t *req);
typedef apr_status_t md_http_perform_cb(md_http_request_t *req);
typedef apr_status_t md_http_multi_perform_cb(apr_array_header_t *requests);

typedef struct md_http_impl_t md_http_impl_t;
struct md_http_impl_t {
    md_http_init_cb *init;
    md_http_req_cleanup_cb *req_cleanup;
    md_http_perform_cb *perform;
    md_http_multi_perform_cb *multi_perform;
};

void md_http_use_implementation(md_http_impl_t *impl);



#endif /* md_http_h */
