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

#include <assert.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include <jansson_config.h>
/* jansson thinks everyone compiles with the platform's cc in its fullest capabilities */
#undef   JSON_INLINE
#define JSON_INLINE 
#include <jansson.h>

#include "md_json.h"
#include "md_log.h"
#include "md_http.h"
#include "md_util.h"

struct md_json_t {
    apr_pool_t *p;
    json_t *j;
};

static void init_dummy()
{
    /* jansson wants to inline static function that we never call and this,
     * -Wunused-function triggers and generated unnecessary warnings. */
    (void)json_decrefp;
    (void)json_object_set_nocheck;
    (void)json_object_iter_set;
    (void)json_array_set;
    (void)json_array_append;
    (void)json_array_insert;
}

/**************************************************************************************************/
/* lifecylce */

static apr_status_t json_pool_cleanup(void *data)
{
    md_json_t *json = data;
    if (json) {
        md_json_destroy(json);
    }
    return APR_SUCCESS;
}

static md_json_t *json_create(apr_pool_t *pool, json_t *j)
{
    md_json_t *json;
    
    (void)init_dummy;
    
    if (!j) {
        apr_abortfunc_t abfn = apr_pool_abort_get(pool);
        if (abfn) {
            abfn(APR_ENOMEM);
        }
        assert(j != NULL); /* failsafe in case abort is unset */
    }
    json = apr_pcalloc(pool, sizeof(*json));
    json->p = pool;
    json->j = j;
    apr_pool_cleanup_register(pool, json, json_pool_cleanup, apr_pool_cleanup_null);
        
    return json;
}

md_json_t *md_json_create(apr_pool_t *pool)
{
    return json_create(pool, json_object());
}

void md_json_destroy(md_json_t *json)
{
    if (json && json->j) {
        json_decref(json->j);
        json->j = NULL;
    }
}

md_json_t *md_json_copy(apr_pool_t *pool, md_json_t *json)
{
    return json_create(pool, json_copy(json->j));
}

md_json_t *md_json_clone(apr_pool_t *pool, md_json_t *json)
{
    return json_create(pool, json_deep_copy(json->j));
}

/**************************************************************************************************/
/* selectors */


static json_t *select(md_json_t *json, va_list ap)
{
    json_t *j;
    const char *key;
    
    j = json->j;
    key = va_arg(ap, char *);
    while (key && j) {
        j = json_object_get(j, key);
        key = va_arg(ap, char *);
    }
    return j;
}

static json_t *select_parent(const char **child_key, int create, md_json_t *json, va_list ap)
{
    const char *key, *next;
    json_t *j, *jn;
    
    *child_key = NULL;
    j = json->j;
    key = va_arg(ap, char *);
    while (key && j) {
        next = va_arg(ap, char *);
        if (next) {
            jn = json_object_get(j, key);
            if (!jn && create) {
                jn = json_object();
                json_object_set_new(j, key, jn);
            }
            j = jn;
        }
        else {
            *child_key = key;
        }
        key = next;
    }
    return j;
}

static apr_status_t select_add(json_t *val, md_json_t *json, va_list ap)
{
    const char *key;
    json_t *j, *aj;
    
    j = select_parent(&key, 1, json, ap);
    
    if (!j || !json_is_object(j)) {
        json_decref(val);
        return APR_EINVAL;
    }
    
    aj = json_object_get(j, key);
    if (!aj) {
        aj = json_array();
        json_object_set_new(j, key, aj);
    }
    
    if (!json_is_array(aj)) {
        json_decref(val);
        return APR_EINVAL;
    }

    json_array_append(aj, val);
    return APR_SUCCESS;
}

static apr_status_t select_set(json_t *val, md_json_t *json, va_list ap)
{
    const char *key;
    json_t *j;
    
    j = select_parent(&key, 1, json, ap);
    
    if (key) {
        if (!j || !json_is_object(j)) {
            return APR_EINVAL;
        }
        json_incref(val);
        json_object_set(j, key, val);
    }
    else {
        /* replace */
        if (json->j) {
            json_decref(json->j);
        }
        json_incref(val);
        json->j = val;
    }
    return APR_SUCCESS;
}

static apr_status_t select_set_new(json_t *val, md_json_t *json, va_list ap)
{
    const char *key;
    json_t *j;
    
    j = select_parent(&key, 1, json, ap);
    
    if (!j || !json_is_object(j)) {
        json_decref(val);
        return APR_EINVAL;
    }
    
    if (key) {
        json_object_set_new(j, key, val);
    }
    else {
        /* replace */
        if (json->j) {
            json_decref(json->j);
        }
        json->j = val;
    }
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* booleans */

int md_json_getb(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);

    return j? json_is_true(j) : 0;
}

apr_status_t md_json_setb(int value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = select_set_new(json_boolean(value), json, ap);
    va_end(ap);
    return rv;
}

/**************************************************************************************************/
/* numbers */

double md_json_getn(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);
    return (j && json_is_number(j))? json_number_value(j) : 0.0;
}

apr_status_t md_json_setn(double value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = select_set_new(json_real(value), json, ap);
    va_end(ap);
    return rv;
}

/**************************************************************************************************/
/* longs */

long md_json_getl(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);
    return (long)((j && json_is_number(j))? json_integer_value(j) : 0L);
}

apr_status_t md_json_setl(long value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = select_set_new(json_integer(value), json, ap);
    va_end(ap);
    return rv;
}

/**************************************************************************************************/
/* strings */

const char *md_json_gets(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);

    return (j && json_is_string(j))? json_string_value(j) : NULL;
}

const char *md_json_dups(apr_pool_t *p, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);

    return (j && json_is_string(j))? apr_pstrdup(p, json_string_value(j)) : NULL;
}

apr_status_t md_json_sets(const char *value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = select_set_new(json_string(value), json, ap);
    va_end(ap);
    return rv;
}

/**************************************************************************************************/
/* json itself */

md_json_t *md_json_getj(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);
    
    if (j) {
        if (j == json->j) {
            return json;
        }
        json_incref(j);
        return json_create(json->p, j);
    }
    return NULL;
}

apr_status_t md_json_setj(md_json_t *value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = select_set(value->j, json, ap);
    va_end(ap);
    return rv;
}

apr_status_t md_json_addj(md_json_t *value, md_json_t *json, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, json);
    rv = select_add(value->j, json, ap);
    va_end(ap);
    return rv;
}


/**************************************************************************************************/
/* arrays / objects */

apr_status_t md_json_clr(md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);

    if (j && json_is_object(j)) {
        json_object_clear(j);
    }
    else if (j && json_is_array(j)) {
        json_array_clear(j);
    }
    return APR_SUCCESS;
}

apr_status_t md_json_del(md_json_t *json, ...)
{
    const char *key;
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select_parent(&key, 0, json, ap);
    va_end(ap);
    
    if (key && j && json_is_object(j)) {
        json_object_del(j, key);
    }
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* object strings */

apr_status_t md_json_gets_dict(apr_table_t *dict, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);

    if (j && json_is_object(j)) {
        const char *key;
        json_t *val;
        
        json_object_foreach(j, key, val) {
            if (json_is_string(val)) {
                apr_table_set(dict, key, json_string_value(val));
            }
        }
        return APR_SUCCESS;
    }
    return APR_ENOENT;
}

static int object_set(void *data, const char *key, const char *val)
{
    json_t *j = data, *nj = json_string(val);
    json_object_set(j, key, nj);
    json_decref(nj);
    return 1;
}
 
apr_status_t md_json_sets_dict(apr_table_t *dict, md_json_t *json, ...)
{
    json_t *nj, *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);
    
    if (!j || !json_is_object(j)) {
        const char *key;
        
        va_start(ap, json);
        j = select_parent(&key, 1, json, ap);
        va_end(ap);
        
        if (!key || !j || !json_is_object(j)) {
            return APR_EINVAL;
        }
        nj = json_object();
        json_object_set_new(j, key, nj);
        j = nj; 
    }
    
    apr_table_do(object_set, j, dict, NULL);
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* conversions */

apr_status_t md_json_pass_to(void *value, md_json_t *json, apr_pool_t *p)
{
    (void)p;
    return md_json_setj(value, json, NULL);
}

apr_status_t md_json_pass_from(void **pvalue, md_json_t *json, apr_pool_t *p)
{
    (void)p;
    *pvalue = json;
    return APR_SUCCESS;
}

apr_status_t md_json_clone_to(void *value, md_json_t *json, apr_pool_t *p)
{
    return md_json_setj(md_json_clone(p, value), json, NULL);
}

apr_status_t md_json_clone_from(void **pvalue, md_json_t *json, apr_pool_t *p)
{
    *pvalue = md_json_clone(p, json);
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* array generic */

apr_status_t md_json_geta(apr_array_header_t *a, md_json_from_cb *cb, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);
    
    if (j && json_is_array(j)) {
        size_t index;
        json_t *val;
        md_json_t wrap;
        void *element;
        
        wrap.p = a->pool;
        json_array_foreach(j, index, val) {
            wrap.j = val;
            if ((APR_SUCCESS == cb(&element, &wrap, wrap.p))) {
                APR_ARRAY_PUSH(a, void*) = element;
            }
        }
        return APR_SUCCESS;
    }
    return APR_ENOENT;
}

apr_status_t md_json_seta(apr_array_header_t *a, md_json_to_cb *cb, md_json_t *json, ...)
{
    json_t *nj, *j;
    md_json_t wrap;
    apr_status_t rv = APR_SUCCESS;
    va_list ap;
    int i;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);
    
    if (!j || !json_is_array(j)) {
        const char *key;
        
        va_start(ap, json);
        j = select_parent(&key, 1, json, ap);
        va_end(ap);
        
        if (!key || !j || !json_is_object(j)) {
            return APR_EINVAL;
        }
        nj = json_array();
        json_object_set_new(j, key, nj);
        j = nj; 
    }
    
    json_array_clear(j);
    wrap.p = json->p;
    nj = NULL;
    for (i = 0; i < a->nelts; ++i) {
        if (NULL == nj) {
            nj = json_string("");
        }
        wrap.j = nj;
        if (APR_SUCCESS == (rv = cb(APR_ARRAY_IDX(a, i, void*), &wrap, json->p))) {
            json_array_append(j, wrap.j);
            if (wrap.j == nj) {
                nj = NULL;
            };
        }
    }
    if (nj) {
        json_decref(nj);
    }
    return rv;
}

/**************************************************************************************************/
/* array strings */

apr_status_t md_json_getsa(apr_array_header_t *a, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);

    if (j && json_is_array(j)) {
        size_t index;
        json_t *val;
        
        json_array_foreach(j, index, val) {
            if (json_is_string(val)) {
                APR_ARRAY_PUSH(a, const char *) = json_string_value(val);
            }
        }
        return APR_SUCCESS;
    }
    return APR_ENOENT;
}

apr_status_t md_json_dupsa(apr_array_header_t *a, apr_pool_t *p, md_json_t *json, ...)
{
    json_t *j;
    va_list ap;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);

    if (j && json_is_array(j)) {
        size_t index;
        json_t *val;
        
        json_array_foreach(j, index, val) {
            if (json_is_string(val)) {
                APR_ARRAY_PUSH(a, const char *) = apr_pstrdup(p, json_string_value(val));
            }
        }
        return APR_SUCCESS;
    }
    return APR_ENOENT;
}

apr_status_t md_json_setsa(apr_array_header_t *a, md_json_t *json, ...)
{
    json_t *nj, *j;
    va_list ap;
    int i;
    
    va_start(ap, json);
    j = select(json, ap);
    va_end(ap);
    
    if (!j || !json_is_array(j)) {
        const char *key;
        
        va_start(ap, json);
        j = select_parent(&key, 1, json, ap);
        va_end(ap);
        
        if (!key || !j || !json_is_object(j)) {
            return APR_EINVAL;
        }
        nj = json_array();
        json_object_set_new(j, key, nj);
        j = nj; 
    }
    
    json_array_clear(j);
    for (i = 0; i < a->nelts; ++i) {
        json_array_append_new(j, json_string(APR_ARRAY_IDX(a, i, const char*)));
    }
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* formatting, parsing */

static int dump_cb(const char *buffer, size_t len, void *baton)
{
    apr_bucket_brigade *bb = baton;
    apr_status_t rv;
    
    rv = apr_brigade_write(bb, NULL, NULL, buffer, len);
    return (rv == APR_SUCCESS)? 0 : -1;
}

apr_status_t md_json_writeb(md_json_t *json, md_json_fmt_t fmt, apr_bucket_brigade *bb)
{
    size_t flags = (fmt == MD_JSON_FMT_COMPACT)? JSON_COMPACT : JSON_INDENT(2); 
    int rv = json_dump_callback(json->j, dump_cb, bb, flags);
    return rv? APR_EGENERAL : APR_SUCCESS;
}

const char *md_json_writep(md_json_t *json, md_json_fmt_t fmt, apr_pool_t *pool)
{
    size_t flags = (fmt == MD_JSON_FMT_COMPACT)? JSON_COMPACT : JSON_INDENT(2); 
    size_t jlen = json_dumpb(json->j, NULL, 0, flags);
    char *s;
    
    if (jlen == 0) {
        return NULL;
    }
    s = apr_palloc(pool, jlen+1);
    jlen = json_dumpb(json->j, s, jlen, flags);
    s[jlen] = '\0';
    return s;
}

static int fdump_cb(const char *buffer, size_t blen, void *baton)
{
    apr_file_t *f = baton;
    apr_size_t len = blen;
    apr_status_t rv;
    
    rv = apr_file_write(f, buffer, &len);
    return (APR_SUCCESS == rv)? 0 : -1;
}

apr_status_t md_json_writef(md_json_t *json, md_json_fmt_t fmt, apr_file_t *f)
{
    size_t flags = (fmt == MD_JSON_FMT_COMPACT)? JSON_COMPACT : JSON_INDENT(2); 
    int rv = json_dump_callback(json->j, fdump_cb, f, flags);
    return rv? APR_EGENERAL : APR_SUCCESS;
}

apr_status_t md_json_fcreatex(md_json_t *json, apr_pool_t *p, md_json_fmt_t fmt, const char *fpath)
{
    apr_status_t rv;
    apr_file_t *f;
    
    rv = md_util_fcreatex(&f, fpath, p);
    if (APR_SUCCESS == rv) {
        rv = md_json_writef(json, fmt, f);
        apr_file_close(f);
    }
    return rv;
}

typedef struct {
    md_json_t *json;
    md_json_fmt_t fmt;
} j_write_ctx;

static apr_status_t write_json(void *baton, apr_file_t *f, apr_pool_t *p)
{
    j_write_ctx *ctx = baton;
    return md_json_writef(ctx->json, ctx->fmt, f);
}

apr_status_t md_json_freplace(md_json_t *json, apr_pool_t *p, md_json_fmt_t fmt, const char *fpath)
{
    j_write_ctx ctx;
    ctx.json = json;
    ctx.fmt = fmt;
    return md_util_freplace(fpath, p, write_json, &ctx);
}

apr_status_t md_json_readd(md_json_t **pjson, apr_pool_t *pool, const char *data, size_t data_len)
{
    json_error_t error;
    json_t *j;
    
    j = json_loadb(data, data_len, 0, &error);
    if (!j) {
        return APR_EINVAL;
    }
    *pjson = json_create(pool, j);
    return APR_SUCCESS;
}

static size_t load_cb(void *data, size_t max_len, void *baton)
{
    apr_bucket_brigade *body = baton;
    size_t blen, read_len = 0;
    const char *bdata;
    char *dest = data;
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
                memcpy(dest, bdata, blen);
                read_len += blen;
                max_len -= blen;
                dest += blen;
            }
            else {
                body = NULL;
                if (!APR_STATUS_IS_EOF(rv)) {
                    /* everything beside EOF is an error */
                    read_len = (size_t)-1;
                }
            }
        }
        APR_BUCKET_REMOVE(b);
        apr_bucket_delete(b);
    }
    
    return read_len;
}

apr_status_t md_json_readb(md_json_t **pjson, apr_pool_t *pool, apr_bucket_brigade *bb)
{
    json_error_t error;
    json_t *j;
    
    j = json_load_callback(load_cb, bb, 0, &error);
    if (!j) {
        return APR_EINVAL;
    }
    *pjson = json_create(pool, j);
    return APR_SUCCESS;
}

static size_t load_file_cb(void *data, size_t max_len, void *baton)
{
    apr_file_t *f = baton;
    apr_size_t len = max_len;
    apr_status_t rv;
    
    rv = apr_file_read(f, data, &len);
    if (APR_SUCCESS == rv) {
        return len;
    }
    else if (APR_EOF == rv) {
        return 0;
    }
    return (size_t)-1;
}

apr_status_t md_json_readf(md_json_t **pjson, apr_pool_t *p, const char *fpath)
{
    apr_file_t *f;
    json_t *j;
    apr_status_t rv;
    json_error_t error;
    
    rv = apr_file_open(&f, fpath, APR_FOPEN_READ, 0, p);
    if (rv == APR_SUCCESS) {
        j = json_load_callback(load_file_cb, f, 0, &error);
        if (j) {
            *pjson = json_create(p, j);
        }
        apr_file_close(f);
        return *pjson? APR_SUCCESS : APR_EINVAL;
    }
    return rv;
}

/**************************************************************************************************/
/* http get */

apr_status_t md_json_read_http(md_json_t **pjson, apr_pool_t *pool, const md_http_response_t *res)
{
    apr_status_t rv = APR_EINVAL;
    if (res->rv == APR_SUCCESS) {
        const char *ctype = apr_table_get(res->headers, "content-type");
        if (ctype && res->body && (strstr(ctype, "/json") || strstr(ctype, "+json"))) {
            rv = md_json_readb(pjson, pool, res->body);
        }
    }
    return rv;
}

typedef struct {
    apr_status_t rv;
    apr_pool_t *pool;
    md_json_t *json;
} resp_data;

static apr_status_t json_resp_cb(const md_http_response_t *res)
{
    resp_data *resp = res->req->baton;
    return md_json_read_http(&resp->json, resp->pool, res);
}

apr_status_t md_json_http_get(md_json_t **pjson, apr_pool_t *pool,
                              struct md_http_t *http, const char *url)
{
    long req_id;
    apr_status_t rv;
    resp_data resp;
    
    memset(&resp, 0, sizeof(resp));
    resp.pool = pool;
    
    rv = md_http_GET(http, url, NULL, json_resp_cb, &resp, &req_id);
    
    if (rv == APR_SUCCESS) {
        md_http_await(http, req_id);
        *pjson = resp.json;
        return resp.rv;
    }
    *pjson = NULL;
    return rv;
}

