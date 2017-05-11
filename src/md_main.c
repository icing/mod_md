/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
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

#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_buckets.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_protocol.h>

#include <jansson.h>

#include "md.h"
#include "md_json.h"
#include "md_http.h"
#include "mod_md.h"
#include "md_version.h"

static void usage(const char *msg) 
{
    if (msg) {
        fprintf(stderr, "%s", msg);
    }
    fprintf(stderr, "usage: a2md ca-url\n");
}

static apr_status_t resp_cb(const md_http_response *res)
{
    const md_http_request *req = res->req;
    
    if (res->rv == APR_SUCCESS) {
        apr_off_t len = 0;
        if (res->body) {
            apr_brigade_length(res->body, 1, &len);
        }
        fprintf(stderr, "response(%ld): %s %s -> %d, DATA %ld\n",
                req->id, req->method, req->url, res->status, (long)len);
    }
    else {
        fprintf(stderr, "response(%ld): %s %s -> error %d\n", 
                req->id, req->method, req->url, res->rv);
    }
    return res->rv;
}

static apr_status_t run(apr_pool_t *pool, int argc, char *argv[]) 
{
    md_http *http;
    apr_status_t rv;
    long req_id;
    const char *url, *data;
    md_json *json;
    
    rv = md_http_create(&http, pool);
    if (rv != APR_SUCCESS) return rv;
    
    while (argc >  0) {
        if (argc > 1) {
            data = argv[0];
            url = argv[1];
            argc -= 2;
            argv += 2;
            
            if (!strcmp("json", data)) {
                rv = md_json_http_get(&json, pool, http, url);
                if (rv == APR_SUCCESS) {
                    fprintf(stderr, "GET %s -> %s\n", url,  
                            md_json_writep(json, MD_JSON_FMT_INDENT, pool)); 
                }
                else {
                    fprintf(stderr, "json failed: %d\n", rv); 
                }
            }
            else {
                rv = md_http_POSTd(http, url, NULL, data, strlen(data), resp_cb, NULL, &req_id);
            }
        }
        else {
            url = argv[0];
            --argc;
            --argc;
            rv = md_http_GET(http, url, NULL, resp_cb, NULL, &req_id);
        }
    }
    
    if (rv == APR_SUCCESS) {
        rv = md_http_await(http, req_id);
    }
    
    return rv;
}

int main(int argc, char *argv[])
{
    apr_allocator_t *allocator;
    apr_status_t status;
    apr_pool_t *pool;
    
    if (argc <= 1) {
        usage(NULL);
        return 2;
    }
    
    apr_allocator_create(&allocator);
    status = apr_pool_create_ex(&pool, NULL, NULL, allocator);
    if (status == APR_SUCCESS) {
        status = run(pool, argc-1, argv+1);
    }
    else {
        fprintf(stderr, "error initializing pool\n");
    }
    
    return (status == APR_SUCCESS)? 0 : 1;
}
