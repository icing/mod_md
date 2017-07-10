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
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_log.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_util.h"

/**************************************************************************************************/
/* file system based implementation of md_store_t */

typedef struct md_store_fs_t md_store_fs_t;
struct md_store_fs_t {
    md_store_t s;
    
    apr_pool_t *p;          /* duplicate for convenience */
    const char *base;       /* base directory of store */
};

#define FS_STORE(store)     (md_store_fs_t*)(((char*)store)-offsetof(md_store_fs_t, s))

static void fs_destroy(md_store_t *store);

static apr_status_t fs_load(md_store_t *store, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void **pvalue, apr_pool_t *p);
static apr_status_t fs_save(md_store_t *store, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void *value, int create);
static apr_status_t fs_remove(md_store_t *store, md_store_group_t group, 
                              const char *name, const char *aspect, 
                              apr_pool_t *p, int force);
static apr_status_t fs_purge(md_store_t *store, md_store_group_t group, const char *name);
static apr_status_t fs_move(md_store_t *store, md_store_group_t from, md_store_group_t to, 
                            const char *name, int archive);
static apr_status_t fs_iterate(md_store_inspect *inspect, void *baton, md_store_t *store, 
                               md_store_group_t group,  const char *pattern,
                               const char *aspect, md_store_vtype_t vtype);


apr_status_t md_store_fs_init(md_store_t **pstore, apr_pool_t *p, const char *path, int create)
{
    md_store_fs_t *s_fs;
    apr_status_t rv = APR_SUCCESS;
    
    s_fs = apr_pcalloc(p, sizeof(*s_fs));
    s_fs->p = s_fs->s.p = p;
    s_fs->s.destroy = fs_destroy;

    s_fs->s.load = fs_load;
    s_fs->s.save = fs_save;
    s_fs->s.remove = fs_remove;
    s_fs->s.move = fs_move;
    s_fs->s.purge = fs_purge;
    s_fs->s.iterate = fs_iterate;

    s_fs->base = apr_pstrdup(p, path);
    
    if (APR_SUCCESS != (rv = md_util_is_dir(s_fs->base, p))) {
        if (APR_STATUS_IS_ENOENT(rv) && create) {
            rv = apr_dir_make_recursive(s_fs->base, MD_FPROT_D_UONLY, p);
        }
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, s_fs->p, "init fs store at %s", path);
        }
    }
    *pstore = (rv == APR_SUCCESS)? &(s_fs->s) : NULL;
    return rv;
}

static void fs_destroy(md_store_t *store)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    s_fs->s.p = NULL;
}

static apr_status_t fs_fload(void **pvalue, const char *fpath, md_store_vtype_t vtype, 
                             apr_pool_t *p, apr_pool_t *ptemp)
{
    apr_status_t rv;
    if (pvalue != NULL) {
        switch (vtype) {
            case MD_SV_TEXT:
                rv = md_text_fread8k((const char **)pvalue, p, fpath);
                break;
            case MD_SV_JSON:
                rv = md_json_readf((md_json_t **)pvalue, p, fpath);
                break;
            case MD_SV_CERT:
                rv = md_cert_fload((md_cert_t **)pvalue, p, fpath);
                break;
            case MD_SV_PKEY:
                rv = md_pkey_fload((md_pkey_t **)pvalue, p, fpath);
                break;
            case MD_SV_CHAIN:
                rv = md_chain_fload((apr_array_header_t **)pvalue, p, fpath);
                break;
            default:
                rv = APR_ENOTIMPL;
                break;
        }
    }
    else { /* check for existence only */
        rv = md_util_is_file(fpath, p);
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, ptemp, "loading type %d from %s", vtype, fpath);
    return rv;
}

static apr_status_t pfs_load(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
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
    
    rv = md_util_path_merge(&fpath, ptemp, s_fs->base, groupname, name, aspect, NULL);
    if (APR_SUCCESS == rv) {
        rv = fs_fload(pvalue, fpath, vtype, p, ptemp);
    }
    return rv;
}

static apr_status_t pfs_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
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
    
    if (APR_SUCCESS == (rv = md_util_path_merge(&dir, ptemp, s_fs->base, groupname, name, NULL))
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

static apr_status_t pfs_remove(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
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
    
    if (APR_SUCCESS == (rv = md_util_path_merge(&dir, ptemp, s_fs->base, groupname, name, NULL))
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

static apr_status_t fs_load(md_store_t *store, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void **pvalue, apr_pool_t *p)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_load, s_fs, p, group, name, aspect, vtype, pvalue, NULL);
}

static apr_status_t fs_save(md_store_t *store, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void *value, int create)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_save, s_fs, s_fs->p, group, name, aspect, 
                            vtype, value, create, NULL);
}

static apr_status_t fs_remove(md_store_t *store, md_store_group_t group, 
                              const char *name, const char *aspect, 
                              apr_pool_t *p, int force)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_remove, s_fs, p, group, name, aspect, force, NULL);
}

static apr_status_t pfs_purge(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *dir, *name, *groupname;
    md_store_group_t group;
    apr_status_t rv;
    
    group = va_arg(ap, int);
    name = va_arg(ap, const char*);
    
    groupname = md_store_group_name(group);

    if (APR_SUCCESS == (rv = md_util_path_merge(&dir, ptemp, s_fs->base, groupname, name, NULL))) {
        /* Remove all files in dir, there should be no sub-dirs */
        rv = md_util_rm_recursive(dir, ptemp, 1);
    }
    return APR_SUCCESS;
}

static apr_status_t fs_purge(md_store_t *store, md_store_group_t group, const char *name)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_purge, s_fs, store->p, group, name, NULL);
}

/**************************************************************************************************/
/* iteration */

typedef struct {
    md_store_fs_t *s_fs;
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
        && APR_SUCCESS == (rv = fs_fload(&value, fpath, ctx->vtype, p, ptemp))) {
        if (!ctx->inspect(ctx->baton, name, ctx->aspect, ctx->vtype, value, ptemp)) {
            return APR_EOF;
        }
    }
    return rv;
}

static apr_status_t fs_iterate(md_store_inspect *inspect, void *baton, md_store_t *store, 
                               md_store_group_t group, const char *pattern, 
                               const char *aspect, md_store_vtype_t vtype)
{
    const char *groupname;
    apr_status_t rv;
    inspect_ctx ctx;
    
    ctx.s_fs = FS_STORE(store);
    ctx.group = group;
    ctx.pattern = pattern;
    ctx.aspect = aspect;
    ctx.vtype = vtype;
    ctx.inspect = inspect;
    ctx.baton = baton;
    groupname = md_store_group_name(group);

    rv = md_util_files_do(insp, &ctx, ctx.s_fs->p, ctx.s_fs->base, 
                          groupname, ctx.pattern, aspect, NULL);
    
    return rv;
}

/**************************************************************************************************/
/* moving */

static apr_status_t pfs_move(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
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

    rv = md_util_path_merge(&from_dir, ptemp, s_fs->base, from_group, name, NULL);
    if (APR_SUCCESS != rv) goto out;
    rv = md_util_path_merge(&to_dir, ptemp, s_fs->base, to_group, name, NULL);
    if (APR_SUCCESS != rv) goto out;
    
    if (APR_SUCCESS != (rv = md_util_is_dir(from_dir, ptemp))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "source is no dir: %s", from_dir);
        goto out;
    }
    
    rv = md_util_is_dir(to_dir, ptemp);
    if (APR_SUCCESS == rv) {
        int n = 1;
        const char *narch_dir;

        rv = md_util_path_merge(&dir, ptemp, s_fs->base, md_store_group_name(MD_SG_ARCHIVE), NULL);
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

static apr_status_t fs_move(md_store_t *store, md_store_group_t from, md_store_group_t to, 
                            const char *name, int archive)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_move, s_fs, store->p, from, to, name, archive, NULL);
}
