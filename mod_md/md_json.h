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

#ifndef mod_md_md_json_h
#define mod_md_md_json_h

struct apr_bucket_brigade;
struct apr_file_t;

struct md_http;
struct md_http_response;


typedef struct md_json md_json;

typedef enum {
    MD_JSON_FMT_COMPACT,
    MD_JSON_FMT_INDENT,
} md_json_fmt_t;

md_json *md_json_create(apr_pool_t *pool);
void md_json_destroy(md_json *json);

md_json *md_json_copy(apr_pool_t *pool, md_json *json);
md_json *md_json_clone(apr_pool_t *pool, md_json *json);

/* boolean manipulation */
int md_json_getb(md_json *json, ...);
apr_status_t md_json_setb(int value, md_json *json, ...);

/* number manipulation */
double md_json_getn(md_json *json, ...);
apr_status_t md_json_setn(double value, md_json *json, ...);

/* string manipulation */
const char *md_json_gets(md_json *json, ...);
apr_status_t md_json_sets(const char *s, md_json *json, ...);

/* json manipulation */
md_json *md_json_getj(md_json *json, ...);
apr_status_t md_json_setj(md_json *value, md_json *json, ...);

/* Array/Object manipulation */
apr_status_t md_json_clr(md_json *json, ...);
apr_status_t md_json_del(md_json *json, ...);

/* Manipulating Object String values */
apr_status_t md_json_gets_dict(apr_table_t *dict, md_json *json, ...);
apr_status_t md_json_sets_dict(apr_table_t *dict, md_json *json, ...);

/* Manipulating String Arrays */
apr_status_t md_json_getsa(apr_array_header_t *a, md_json *json, ...);
apr_status_t md_json_setsa(apr_array_header_t *a, md_json *json, ...);

/* serialization & parsing */
apr_status_t md_json_writeb(md_json *json, md_json_fmt_t fmt, struct apr_bucket_brigade *bb);
const char *md_json_writep(md_json *json, md_json_fmt_t fmt, apr_pool_t *pool);
apr_status_t md_json_writef(md_json *json, md_json_fmt_t fmt, struct apr_file_t *f);
apr_status_t md_json_fcreatex(md_json *json, apr_pool_t *p, md_json_fmt_t fmt, const char *fpath);

apr_status_t md_json_readb(md_json **pjson, apr_pool_t *pool, struct apr_bucket_brigade *bb);
apr_status_t md_json_readd(md_json **pjson, apr_pool_t *pool, const char *data, size_t data_len);
apr_status_t md_json_readf(md_json **pjson, apr_pool_t *pool, const char *fpath);

/* http retrieval */
apr_status_t md_json_http_get(md_json **pjson, apr_pool_t *pool,
                              struct md_http *http, const char *url);
apr_status_t md_json_read_http(md_json **pjson, apr_pool_t *pool, 
                               const struct md_http_response *res);

#endif /* md_json_h */
