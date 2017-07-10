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

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_log.h"
#include "md_store.h"
#include "md_store_mem.h"
#include "md_util.h"

/**************************************************************************************************/
/* memory based implementation of md_store_t */

typedef struct md_store_mem_t md_store_mem_t;
struct md_store_mem_t {
    md_store_t s;
    
    apr_pool_t *p;          /* duplicate for convenience */
    md_json_t *data;
};

#define MEM_STORE(store)     (md_store_mem_t*)(((char*)store)-offsetof(md_store_mem_t, s))

static void mem_destroy(md_store_t *store);

static apr_status_t mem_load(md_store_t *store, md_store_group_t group, 
                             const char *name, const char *aspect,  
                             md_store_vtype_t vtype, void **pvalue, apr_pool_t *p);
static apr_status_t mem_save(md_store_t *store, md_store_group_t group, 
                             const char *name, const char *aspect,  
                             md_store_vtype_t vtype, void *value, int create);
static apr_status_t mem_remove(md_store_t *store, md_store_group_t group, 
                               const char *name, const char *aspect, 
                               apr_pool_t *p, int force);
static apr_status_t mem_purge(md_store_t *store, md_store_group_t group, const char *name);
static apr_status_t mem_move(md_store_t *store, md_store_group_t from, md_store_group_t to, 
                             const char *name, int archive);
static apr_status_t mem_iterate(md_store_inspect *inspect, void *baton, md_store_t *store, 
                                md_store_group_t group,  const char *pattern,
                                const char *aspect, md_store_vtype_t vtype);


apr_status_t md_store_mem_init(md_store_t **pstore, apr_pool_t *p)
{
    md_store_mem_t *s_mem;
    apr_status_t rv = APR_SUCCESS;
    
    s_mem = apr_pcalloc(p, sizeof(*s_mem));
    s_mem->p = s_mem->s.p = p;
    s_mem->s.destroy = mem_destroy;

    s_mem->s.load = mem_load;
    s_mem->s.save = mem_save;
    s_mem->s.remove = mem_remove;
    s_mem->s.move = mem_move;
    s_mem->s.purge = mem_purge;
    s_mem->s.iterate = mem_iterate;

    s_mem->data = md_json_create(s_mem->p);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, s_mem->p, "init mem store");
    *pstore = (rv == APR_SUCCESS)? &(s_mem->s) : NULL;
    return rv;
}

static void mem_destroy(md_store_t *store)
{
    md_store_mem_t *s_mem = MEM_STORE(store);
    s_mem->s.p = NULL;
}

#define MD_KEY_VALUE        "value"
#define MD_KEY_TYPE         "type"

#define MD_TYPE_TEXT        "text"
#define MD_TYPE_JSON        "json"
#define MD_TYPE_CERT        "cert"
#define MD_TYPE_PKEY        "pkey"
#define MD_TYPE_CHAIN       "chain"

static apr_status_t to_json(md_json_t **pjson, apr_pool_t *p, md_store_vtype_t vtype, void *value)
{
    md_json_t *json = md_json_create(p);
    apr_status_t rv = APR_SUCCESS;
    apr_array_header_t *chain, *chain64;
    md_cert_t *cert;
    const char *s;
    int i;
    
    switch (vtype) {
        case MD_SV_TEXT:
            json = md_json_create(p);
            md_json_sets(MD_TYPE_TEXT, json, MD_KEY_TYPE, NULL);
            md_json_sets(value, json, MD_KEY_VALUE, NULL);
            break;
        case MD_SV_JSON:
            md_json_sets(MD_TYPE_JSON, json, MD_KEY_TYPE, NULL);
            md_json_setj(md_json_clone(p, value), json, MD_KEY_VALUE, NULL);
            break;
        case MD_SV_CERT:
            md_json_sets(MD_TYPE_CERT, json, MD_KEY_TYPE, NULL);
            cert = value;
            if (APR_SUCCESS == (rv = md_cert_to_base64url(&s, cert, p))) {
                md_json_sets(s, json, MD_KEY_VALUE, NULL);
            }
            break;
        case MD_SV_PKEY:
            md_json_sets(MD_TYPE_PKEY, json, MD_KEY_TYPE, NULL);
            if (APR_SUCCESS == (rv = md_pkey_to_base64url(&s, value, p))) {
                md_json_sets(s, json, MD_KEY_VALUE, NULL);
            }
            break;
        case MD_SV_CHAIN:
            md_json_sets(MD_TYPE_CHAIN, json, MD_KEY_TYPE, NULL);
            chain = value;
            chain64 = apr_array_make(p, chain->nelts, sizeof(char *));
            for (i = 0; i < chain->nelts; ++i) {
                cert = APR_ARRAY_IDX(chain, i, md_cert_t *);
                if (APR_SUCCESS != (rv = md_cert_to_base64url(&s, cert, p))) {
                    break;
                }
                APR_ARRAY_PUSH(chain64, const char*) = s; 
            }
            md_json_setsa(chain64, json, MD_KEY_VALUE, NULL);
            break;
        default:
            rv = APR_ENOTIMPL;
            break;
    }
    *pjson = (APR_SUCCESS == rv)? json : NULL;
    return rv;
}

static const char *type_name(md_store_vtype_t vtype)
{
    switch (vtype) {
        case MD_SV_TEXT:
            return MD_TYPE_TEXT;
        case MD_SV_JSON:
            return MD_TYPE_JSON;
        case MD_SV_CERT:
            return MD_TYPE_CERT;
        case MD_SV_PKEY:
            return MD_TYPE_PKEY;
        case MD_SV_CHAIN:
            return MD_TYPE_CHAIN;
        default:
            return "UNKNOWN";
    }
}

static int has_type(md_json_t *json, md_store_vtype_t vtype)
{
    const char *t;
    if (json) {
        t = md_json_gets(json, MD_KEY_TYPE, NULL);
        if (!t || strcmp(t, type_name(vtype))) {
            return APR_EINVAL;
        }
    }
    return APR_SUCCESS;
}

static apr_status_t from_json(void **pvalue, apr_pool_t *p, md_store_vtype_t vtype, md_json_t *json)
{
    apr_status_t rv = APR_SUCCESS;
    const char *s64;
    apr_array_header_t *chain64, *chain;
    md_cert_t *cert;
    int i;
    
    if (pvalue != NULL) {
        *pvalue = NULL;
        if (!json) {
            return APR_ENOENT;
        }
        if (APR_SUCCESS != has_type(json, vtype)) {
            return APR_EINVAL;
        }
        switch (vtype) {
            case MD_SV_TEXT:
                *pvalue = (void*)md_json_dups(p, json, MD_KEY_VALUE, NULL);
                break;
            case MD_SV_JSON:
                *pvalue = md_json_clone(p, md_json_getj(json, MD_KEY_VALUE, NULL));
                break;
            case MD_SV_CERT:
                s64 = md_json_gets(json, MD_KEY_VALUE, NULL);
                if (s64 && *s64) {
                    rv = md_cert_from_base64url((md_cert_t**)pvalue, s64, p);
                }
                break;
            case MD_SV_PKEY:
                s64 = md_json_gets(json, MD_KEY_VALUE, NULL);
                if (s64 && *s64) {
                    rv = md_pkey_from_base64url((md_pkey_t**)pvalue, s64, p);
                }
                break;
            case MD_SV_CHAIN:
                chain64 = apr_array_make(p, 5, sizeof(char *));
                rv = md_json_getsa(chain64, json, MD_KEY_VALUE, NULL);
                if (APR_SUCCESS == rv) {
                    chain = apr_array_make(p, 5, sizeof(md_cert_t *));
                    for (i = 0; i < chain64->nelts; ++i) {
                        s64 = APR_ARRAY_IDX(chain64, i, const char *);
                        if (APR_SUCCESS != (rv = md_cert_from_base64url(&cert, s64, p))) {
                            break;
                        }
                        APR_ARRAY_PUSH(chain, md_cert_t*) = cert;
                    }
                    if (APR_SUCCESS == rv) {
                        *pvalue = chain;
                    }
                }
                break;
            default:
                rv = APR_ENOTIMPL;
                break;
        }
    }
    else { /* check for existence only */
        rv = json? APR_SUCCESS : APR_ENOENT;
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p, "loading type %d", vtype);
    return rv;
}

static apr_status_t mem_fload(void **pvalue, const char *fpath, md_store_vtype_t vtype, 
                             apr_pool_t *p, apr_pool_t *ptemp)
{
    apr_status_t rv;
    if (pvalue != NULL) {
        switch (vtype) {
            case MD_SV_TEXT:
                break;
            case MD_SV_JSON:
                break;
            case MD_SV_CERT:
                break;
            case MD_SV_PKEY:
                break;
            case MD_SV_CHAIN:
                break;
            default:
                rv = APR_ENOTIMPL;
                break;
        }
    }
    else { /* check for existence only */
    }
    (void)from_json;
    (void)to_json;
    return APR_ENOTIMPL;
}

static apr_status_t pmem_load(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    const char *fpath, *name, *aspect, *groupname;
    md_store_vtype_t vtype;
    md_store_group_t group;
    void **pvalue;
    apr_status_t rv;
    
    group = va_arg(ap, int);
    name = va_arg(ap, const char *);
    aspect = va_arg(ap, const char *);
    vtype = va_arg(ap, int);
    pvalue= va_arg(ap, void **);
        
    groupname = md_store_group_name(group);
    
    rv = md_util_path_merge(&fpath, ptemp, "/", groupname, name, aspect, NULL);
    if (APR_SUCCESS == rv) {
        rv = mem_fload(pvalue, fpath, vtype, p, ptemp);
    }
    return rv;
}

static apr_status_t pmem_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    const char *dir, *fpath, *name, *aspect, *groupname;
    md_store_vtype_t vtype;
    md_store_group_t group;
    void *value;
    int create;
    apr_status_t rv;
    
    group = va_arg(ap, int);
    name = va_arg(ap, const char*);
    aspect = va_arg(ap, const char*);
    vtype = va_arg(ap, int);
    value = va_arg(ap, void *);
    create = va_arg(ap, int);
    
    groupname = md_store_group_name(group);
    
    if (APR_SUCCESS == (rv = md_util_path_merge(&dir, ptemp, "/", groupname, name, NULL))
        && APR_SUCCESS == (rv = apr_dir_make_recursive(dir, MD_FPROT_D_UONLY, p)) 
        && APR_SUCCESS == (rv = md_util_path_merge(&fpath, ptemp, dir, aspect, NULL))) {
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "storing in %s", fpath);
        switch (vtype) {
            case MD_SV_TEXT:
                rv = (create? md_text_fcreatex(fpath,p, value)
                      : md_text_freplace(fpath, p, value));
                break;
            case MD_SV_JSON:
                rv = (create? md_json_fcreatex((md_json_t *)value, p, MD_JSON_FMT_INDENT, fpath)
                      : md_json_freplace((md_json_t *)value, p, MD_JSON_FMT_INDENT, fpath));
                break;
            case MD_SV_CERT:
                rv = md_cert_fsave((md_cert_t *)value, ptemp, fpath);
                break;
            case MD_SV_PKEY:
                rv = md_pkey_fsave((md_pkey_t *)value, ptemp, fpath);
                break;
            case MD_SV_CHAIN:
                rv = md_chain_fsave((apr_array_header_t*)value, ptemp, fpath);
                break;
            default:
                return APR_ENOTIMPL;
        }
    }
    return rv;
}

static apr_status_t pmem_remove(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    const char *dir, *name, *fpath, *groupname, *aspect;
    apr_status_t rv;
    int force;
    apr_finfo_t info;
    md_store_group_t group;
    
    group = va_arg(ap, int);
    name = va_arg(ap, const char*);
    aspect = va_arg(ap, const char *);
    force = va_arg(ap, int);
    
    groupname = md_store_group_name(group);
    
    if (APR_SUCCESS == (rv = md_util_path_merge(&dir, ptemp, "/", groupname, name, NULL))
        && APR_SUCCESS == (rv = md_util_path_merge(&fpath, ptemp, dir, aspect, NULL))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "start remove of md %s", name);

        if (APR_SUCCESS != (rv = apr_stat(&info, dir, APR_FINFO_TYPE, ptemp))) {
            if (APR_ENOENT == rv && force) {
                return APR_SUCCESS;
            }
            return rv;
        }
    
        rv = apr_file_remove(fpath, ptemp);
        if (APR_ENOENT == rv && force) {
            rv = APR_SUCCESS;
        }
    }
    return rv;
}

static apr_status_t mem_load(md_store_t *store, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void **pvalue, apr_pool_t *p)
{
    md_store_mem_t *s_mem = MEM_STORE(store);
    return md_util_pool_vdo(pmem_load, s_mem, p, group, name, aspect, vtype, pvalue, NULL);
}

static apr_status_t mem_save(md_store_t *store, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void *value, int create)
{
    md_store_mem_t *s_mem = MEM_STORE(store);
    return md_util_pool_vdo(pmem_save, s_mem, s_mem->p, group, name, aspect, 
                            vtype, value, create, NULL);
}

static apr_status_t mem_remove(md_store_t *store, md_store_group_t group, 
                              const char *name, const char *aspect, 
                              apr_pool_t *p, int force)
{
    md_store_mem_t *s_mem = MEM_STORE(store);
    return md_util_pool_vdo(pmem_remove, s_mem, p, group, name, aspect, force, NULL);
}

static apr_status_t pmem_purge(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    const char *dir, *name, *groupname;
    md_store_group_t group;
    apr_status_t rv;
    
    group = va_arg(ap, int);
    name = va_arg(ap, const char*);
    
    groupname = md_store_group_name(group);

    if (APR_SUCCESS == (rv = md_util_path_merge(&dir, ptemp, "/", groupname, name, NULL))) {
        /* Remove all files in dir, there should be no sub-dirs */
        rv = md_util_rm_recursive(dir, ptemp, 1);
    }
    return APR_SUCCESS;
}

static apr_status_t mem_purge(md_store_t *store, md_store_group_t group, const char *name)
{
    md_store_mem_t *s_mem = MEM_STORE(store);
    return md_util_pool_vdo(pmem_purge, s_mem, store->p, group, name, NULL);
}

/**************************************************************************************************/
/* iteration */

typedef struct {
    md_store_mem_t *s_mem;
    md_store_group_t group;
    const char *pattern;
    const char *aspect;
    md_store_vtype_t vtype;
    md_store_inspect *inspect;
    void *baton;
} inspect_ctx;

static apr_status_t insp(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                         const char *dir, const char *name, apr_filetype_e ftype)
{
    inspect_ctx *ctx = baton;
    apr_status_t rv;
    void *value;
    const char *fpath;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "inspecting value at: %s/%s", dir, name);
    if (APR_SUCCESS == (rv = md_util_path_merge(&fpath, ptemp, dir, name, NULL))
        && APR_SUCCESS == (rv = mem_fload(&value, fpath, ctx->vtype, p, ptemp))) {
        if (!ctx->inspect(ctx->baton, name, ctx->aspect, ctx->vtype, value, ptemp)) {
            return APR_EOF;
        }
    }
    return rv;
}

static apr_status_t mem_iterate(md_store_inspect *inspect, void *baton, md_store_t *store, 
                               md_store_group_t group, const char *pattern, 
                               const char *aspect, md_store_vtype_t vtype)
{
    const char *groupname;
    inspect_ctx ctx;
    
    ctx.s_mem = MEM_STORE(store);
    ctx.group = group;
    ctx.pattern = pattern;
    ctx.aspect = aspect;
    ctx.vtype = vtype;
    ctx.inspect = inspect;
    ctx.baton = baton;
    groupname = md_store_group_name(group);

    (void)insp;
    return APR_ENOTIMPL;
}

/**************************************************************************************************/
/* moving */

static apr_status_t pmem_move(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    const char *name, *from_group, *to_group, *from_dir, *to_dir, *arch_dir, *dir;
    md_store_group_t from, to;
    int archive;
    apr_status_t rv;
    
    from = va_arg(ap, int);
    to = va_arg(ap, int);
    name = va_arg(ap, const char*);
    archive = va_arg(ap, int);
    
    from_group = md_store_group_name(from);
    to_group = md_store_group_name(to);
    if (!strcmp(from_group, to_group)) {
        return APR_EINVAL;
    }

    rv = md_util_path_merge(&from_dir, ptemp, "/", from_group, name, NULL);
    if (APR_SUCCESS != rv) goto out;
    rv = md_util_path_merge(&to_dir, ptemp, "/", to_group, name, NULL);
    if (APR_SUCCESS != rv) goto out;
    
    if (APR_SUCCESS != (rv = md_util_is_dir(from_dir, ptemp))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "source is no dir: %s", from_dir);
        goto out;
    }
    
    rv = md_util_is_dir(to_dir, ptemp);
    if (APR_SUCCESS == rv) {
        int n = 1;
        const char *narch_dir;

        rv = md_util_path_merge(&dir, ptemp, "/", md_store_group_name(MD_SG_ARCHIVE), NULL);
        if (APR_SUCCESS != rv) goto out;
        rv = apr_dir_make_recursive(dir, MD_FPROT_D_UONLY, ptemp); 
        if (APR_SUCCESS != rv) goto out;
        rv = md_util_path_merge(&arch_dir, ptemp, dir, name, NULL);
        if (APR_SUCCESS != rv) goto out;
        
        while (1) {
            narch_dir = apr_psprintf(ptemp, "%s.%d", arch_dir, n);
            rv = apr_dir_make(narch_dir, MD_FPROT_D_UONLY, ptemp);
            if (APR_SUCCESS == rv) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "using archive dir: %s", 
                              narch_dir);
                break;
            }
            else if (APR_EEXIST == rv) {
                ++n;
            }
            else {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "creating archive dir: %s", 
                              narch_dir);
                goto out;
            }
        } 
        
        if (APR_SUCCESS != (rv = apr_file_rename(to_dir, narch_dir, ptemp))) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "rename from %s to %s", 
                              to_dir, narch_dir);
                goto out;
        }
        if (APR_SUCCESS != (rv = apr_file_rename(from_dir, to_dir, ptemp))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "moving %s to %s: %s", 
                          from_dir, to_dir);
            apr_file_rename(narch_dir, to_dir, ptemp);
            goto out;
        }
    }
    else if (APR_STATUS_IS_ENOENT(rv)) {
        if (APR_SUCCESS != (rv = apr_file_rename(from_dir, to_dir, ptemp))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "rename from %s to %s", 
                          from_dir, to_dir);
            goto out;
        }
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "target is no dir: %s", to_dir);
        goto out;
    }
    
out:
    return rv;
}

static apr_status_t mem_move(md_store_t *store, md_store_group_t from, md_store_group_t to, 
                            const char *name, int archive)
{
    md_store_mem_t *s_mem = MEM_STORE(store);
    return md_util_pool_vdo(pmem_move, s_mem, store->p, from, to, name, archive, NULL);
}
