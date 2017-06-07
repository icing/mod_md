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
#include "md_log.h"
#include "md_json.h"
#include "md_store.h"
#include "md_util.h"

/**************************************************************************************************/
/* generic callback handling */

void md_store_destroy(md_store_t *store)
{
    if (store->destroy) store->destroy(store);
}

apr_status_t md_store_load_md(md_t **pmd, md_store_t *store, const char *name, apr_pool_t *p)
{
    return store->load((void**)pmd, store, MD_SG_DOMAINS, name, MD_SV_MD, p);
}

apr_status_t md_store_save_md(md_store_t *store, md_t *md, int create)
{
    return store->save(store, MD_SG_DOMAINS, md->name, MD_SV_MD, md, create);
}

apr_status_t md_store_remove_md(md_store_t *store, const char *name, int force)
{
    return store->remove(store, MD_SG_DOMAINS, name, MD_SV_MD, force);
}

apr_status_t md_store_load_cert(struct md_cert_t **pcert, md_store_t *store, 
                                const char *name, apr_pool_t *p)
{
    return store->load((void**)pcert, store, MD_SG_DOMAINS, name, MD_SV_CERT, p);
}

apr_status_t md_store_save_cert(md_store_t *store, const char *name, struct md_cert_t *cert)
{
    return store->save(store, MD_SG_DOMAINS, name, MD_SV_CERT, cert, 0);
}

apr_status_t md_store_load_pkey(struct md_pkey_t **ppkey, md_store_t *store, 
                                md_store_group_t group,const char *name, apr_pool_t *p)
{
    return store->load((void**)ppkey, store, group, name, MD_SV_PKEY, p);
}

apr_status_t md_store_save_pkey(md_store_t *store, md_store_group_t group, 
                                const char *name, struct md_pkey_t *pkey)
{
    return store->save(store, group, name, MD_SV_PKEY, pkey, 0);
}

apr_status_t md_store_load_chain(struct apr_array_header_t **pchain, md_store_t *store, 
                                const char *name, apr_pool_t *p)
{
    return store->load((void**)pchain, store, MD_SG_DOMAINS, name, MD_SV_CHAIN, p);
}

apr_status_t md_store_save_chain(md_store_t *store, const char *name,
                                 struct apr_array_header_t *chain)
{
    return store->save(store, MD_SG_DOMAINS, name, MD_SV_CHAIN, chain, 0);
}

apr_status_t md_store_load_data(struct md_json_t **pjson, md_store_t *store, 
                                md_store_group_t group, const char *name, apr_pool_t *p)
{
    return store->load((void**)pjson, store, group, name, MD_SV_JSON_DATA, p);
}

apr_status_t md_store_save_data(md_store_t *store, md_store_group_t group, const char *name, 
                                struct md_json_t *json, int create)
{
    return store->save(store, group, name, MD_SV_JSON_DATA, json, create);
}

apr_status_t md_store_iter(md_store_inspect *inspect, void *baton, md_store_t *store, 
                           md_store_group_t group, const char *pattern, md_store_vtype_t vtype)
{
    return store->iterate(inspect, baton, store, group, pattern, vtype);
}

typedef struct {
    apr_pool_t *p;
    apr_array_header_t *mds;
} md_load_ctx;

static int add_md(void *baton, const char *name, md_store_vtype_t vtype, void *value)
{
    md_load_ctx *ctx = baton;
    
    if (MD_SV_MD == vtype) {
        const md_t *md = value;
        
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, "adding md %s", md->name);
        APR_ARRAY_PUSH(ctx->mds, md_t *) = md_clone(ctx->p, md);
    }
    return 1;
}

static int md_name_cmp(const void *v1, const void *v2)
{
    return strcmp((*(const md_t**)v1)->name, (*(const md_t**)v2)->name);
}


apr_status_t md_store_load_mds(apr_array_header_t **pmds, md_store_t *store, apr_pool_t *p)
{
    apr_status_t rv;
    md_load_ctx ctx;
    
    ctx.p = p;
    ctx.mds = apr_array_make(p, 5, sizeof(md_t *));
    if (APR_SUCCESS == (rv = store->iterate(add_md, &ctx, store, MD_SG_DOMAINS, "*", MD_SV_MD))) {
        qsort(ctx.mds->elts, ctx.mds->nelts, sizeof(md_t *), md_name_cmp);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, p, "found %d mds", ctx.mds->nelts);
    }
    *pmds = (APR_SUCCESS == rv)? ctx.mds : NULL;
    return rv;
}

/**************************************************************************************************/
/* file system based implementation */

typedef struct md_store_fs_t md_store_fs_t;
struct md_store_fs_t {
    md_store_t s;
    
    apr_pool_t *p;          /* duplicate for convenience */
    const char *base;       /* base directory of store */
};

#define FS_STORE(store)     (md_store_fs_t*)(((char*)store)-offsetof(md_store_fs_t, s))

static void fs_destroy(md_store_t *store);

static apr_status_t fs_load(void **pvalue, md_store_t *store, 
                            md_store_group_t group, const char *name, 
                            md_store_vtype_t vtype, apr_pool_t *p);
static apr_status_t fs_save(md_store_t *store, 
                            md_store_group_t group, const char *name, 
                            md_store_vtype_t vtype, void *value, int create);
static apr_status_t fs_remove(md_store_t *store, 
                              md_store_group_t group, const char *name, 
                              md_store_vtype_t vtype, int force);
static apr_status_t fs_iterate(md_store_inspect *inspect, void *baton, md_store_t *store, 
                               md_store_group_t group,  const char *pattern,
                               md_store_vtype_t vtype);


apr_status_t md_store_fs_init(md_store_t **pstore, apr_pool_t *p, const char *path)
{
    md_store_fs_t *s_fs;
    apr_status_t rv = APR_SUCCESS;
    
    s_fs = apr_pcalloc(p, sizeof(*s_fs));
    s_fs->p = s_fs->s.p = p;
    s_fs->s.destroy = fs_destroy;

    s_fs->s.load = fs_load;
    s_fs->s.save = fs_save;
    s_fs->s.remove = fs_remove;
    s_fs->s.iterate = fs_iterate;

    s_fs->base = apr_pstrdup(p, path);
    
    if (APR_SUCCESS != (rv = md_util_is_dir(s_fs->base, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, s_fs->p, "init fs store at %s", path);
    }
    *pstore = (rv == APR_SUCCESS)? &(s_fs->s) : NULL;
    return rv;
}

static void fs_destroy(md_store_t *store)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    s_fs->s.p = NULL;
}

static apr_status_t pfs_md_readf(md_t **pmd, const char *fpath, apr_pool_t *p, apr_pool_t *ptemp)
{
    md_json_t *json;
    apr_status_t rv;
    
    *pmd = NULL;
    rv = md_json_readf(&json, ptemp, fpath);
    if (APR_SUCCESS == rv) {
        md_t *md = md_from_json(json, p);
        md->defn_name = apr_pstrdup(p, fpath);
        *pmd = md;
        return APR_SUCCESS;
    }
    return rv;
}

static apr_status_t pfs_md_writef(md_t *md, const char *dir, const char *name, apr_pool_t *p,
                                  int create)
{
    const char *fpath;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = apr_dir_make_recursive(dir, MD_FPROT_D_UONLY, p))) {
        if (APR_SUCCESS == (rv = md_util_path_merge(&fpath, p, dir, name, NULL))) {
            md_json_t *json = md_to_json(md, p);
            return (create? md_json_fcreatex(json, p, MD_JSON_FMT_INDENT, fpath)
                    : md_json_freplace(json, p, MD_JSON_FMT_INDENT, fpath));
        }
    }
    return rv;
}

#define FS_DN_ACCOUNTS     "accounts"
#define FS_DN_DOMAINS      "domains"

#define FS_FN_MD_JSON      "md.json"
#define FS_FN_CERT_PEM     "cert.pem"
#define FS_FN_PKEY_PEM     "key.pem"
#define FS_FN_CHAIN_PEM    "chain.pem"
#define FS_FN_JSON_DATA    "data.json"

static const char *VTYPE_FNAME[] = {
    FS_FN_MD_JSON,
    FS_FN_CERT_PEM,
    FS_FN_PKEY_PEM,
    FS_FN_CHAIN_PEM,
    FS_FN_JSON_DATA,
};

static const char *vtype_filename(int vtype)
{
    if (vtype < sizeof(VTYPE_FNAME)/sizeof(VTYPE_FNAME[0])) {
        return VTYPE_FNAME[vtype];
    }
    return "UNKNOWN";
}

static const char *SGROUP_FNAME[] = {
    FS_DN_ACCOUNTS,
    FS_DN_DOMAINS,
};

static const char *sgroup_filename(int group)
{
    if (group < sizeof(VTYPE_FNAME)/sizeof(VTYPE_FNAME[0])) {
        return SGROUP_FNAME[group];
    }
    return "UNKNOWN";
}

static apr_status_t fs_fload(void **pvalue, const char *fpath, md_store_vtype_t vtype, 
                             apr_pool_t *p, apr_pool_t *ptemp)
{
    apr_status_t rv;
    if (pvalue != NULL) {
        switch (vtype) {
            case MD_SV_MD:
                rv = pfs_md_readf((md_t **)pvalue, fpath, p, ptemp);
                break;
            case MD_SV_CERT:
                rv = md_cert_load((md_cert_t **)pvalue, p, fpath);
                break;
            case MD_SV_PKEY:
                rv = md_pkey_load((md_pkey_t **)pvalue, p, fpath);
                break;
            case MD_SV_CHAIN:
                rv = md_cert_load_chain((apr_array_header_t **)pvalue, p, fpath);
                break;
            case MD_SV_JSON_DATA:
                rv = md_json_readf((md_json_t **)pvalue, p, fpath);
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
    const char *fpath, *name, *filename, *groupname;
    md_store_vtype_t vtype;
    md_store_group_t group;
    void **pvalue;
    apr_status_t rv;
    
    pvalue= va_arg(ap, void **);
    group = va_arg(ap, int);
    name = va_arg(ap, const char *);
    vtype = va_arg(ap, int);
        
    groupname = sgroup_filename(group);
    filename = vtype_filename(vtype);
    
    rv = md_util_path_merge(&fpath, ptemp, s_fs->base, groupname, name, filename, NULL);
    if (APR_SUCCESS == rv) {
        rv = fs_fload(pvalue, fpath, vtype, p, ptemp);
    }
    return rv;
}

static apr_status_t pfs_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *dir, *fpath, *name, *filename, *groupname;
    md_store_vtype_t vtype;
    md_store_group_t group;
    void *value;
    int create;
    apr_status_t rv;
    
    group = va_arg(ap, int);
    name = va_arg(ap, const char*);
    vtype = va_arg(ap, int);
    value = va_arg(ap, void *);
    create = va_arg(ap, int);
    
    groupname = sgroup_filename(group);
    filename = vtype_filename(vtype);
    
    if (APR_SUCCESS == (rv = md_util_path_merge(&dir, ptemp, s_fs->base, groupname, name, NULL))
        && APR_SUCCESS == (rv = apr_dir_make_recursive(dir, MD_FPROT_D_UONLY, p)) 
        && APR_SUCCESS == (rv = md_util_path_merge(&fpath, ptemp, dir, filename, NULL))) {
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "storing in %s", fpath);
        switch (vtype) {
            case MD_SV_MD:
                rv = pfs_md_writef((md_t*)value, dir, FS_FN_MD_JSON, ptemp, create);
                break;
            case MD_SV_CERT:
                rv = md_cert_save((md_cert_t *)value, ptemp, fpath);
                break;
            case MD_SV_PKEY:
                rv = md_pkey_save((md_pkey_t *)value, ptemp, fpath);
                break;
            case MD_SV_CHAIN:
                rv = md_cert_save_chain((apr_array_header_t*)value, ptemp, fpath);
                break;
            case MD_SV_JSON_DATA:
                rv = (create? md_json_fcreatex((md_json_t *)value, p, MD_JSON_FMT_INDENT, fpath)
                      : md_json_freplace((md_json_t *)value, p, MD_JSON_FMT_INDENT, fpath));
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
    const char *dir, *name, *fpath, *filename, *groupname;
    apr_status_t rv;
    int force;
    apr_finfo_t info;
    md_store_vtype_t vtype;
    md_store_group_t group;
    
    group = va_arg(ap, int);
    name = va_arg(ap, const char*);
    vtype = va_arg(ap, int);
    force = va_arg(ap, int);
    
    groupname = sgroup_filename(group);
    filename = vtype_filename(vtype);
    
    if (APR_SUCCESS == (rv = md_util_path_merge(&dir, ptemp, s_fs->base, groupname, name, NULL))
        && APR_SUCCESS == (rv = md_util_path_merge(&fpath, ptemp, dir, filename, NULL))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "start remove of md %s", name);

        if (APR_SUCCESS != (rv = apr_stat(&info, dir, APR_FINFO_TYPE, ptemp))) {
            if (APR_ENOENT == rv && force) {
                return APR_SUCCESS;
            }
            return rv;
        }
    
        switch (vtype) {
            case MD_SV_MD:
                switch (info.filetype) {
                    case APR_DIR: /* how it should be */
                        /* TODO: check if there is important data, such as keys or certificates. 
                         * Only remove the md when forced in such cases. */
                        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "remove tree: %s", dir);
                        rv = md_util_ftree_remove(dir, ptemp);
                        break;
                    default:      /* how did that get here? suspicious */
                        if (!force) {
                            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, 
                                          "remove md %s: not a directory at %s", name, dir);
                            return APR_EINVAL;
                        }
                        rv = apr_file_remove(dir, ptemp);
                        break;
                }
                break;
            case MD_SV_CERT:
            case MD_SV_PKEY:
            case MD_SV_CHAIN:
                rv = apr_file_remove(fpath, ptemp);
                if (APR_ENOENT == rv && force) {
                    rv = APR_SUCCESS;
                }
                break;
            default:
                return APR_ENOTIMPL;
        }
    }
    return rv;
}

static apr_status_t fs_load(void **pvalue, md_store_t *store, 
                            md_store_group_t group, const char *name, 
                            md_store_vtype_t vtype, apr_pool_t *p)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_load, s_fs, p, pvalue, group, name, vtype, NULL);
}

static apr_status_t fs_save(md_store_t *store, 
                            md_store_group_t group, const char *name, 
                            md_store_vtype_t vtype, void *value, int create)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_save, s_fs, s_fs->p, group, name, vtype, value, create, NULL);
}

static apr_status_t fs_remove(md_store_t *store, 
                              md_store_group_t group, const char *name, 
                              md_store_vtype_t vtype, int force)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_remove, s_fs, s_fs->p, group, name, vtype, force, NULL);
}

/**************************************************************************************************/
/* iteration */

typedef struct {
    md_store_fs_t *s_fs;
    md_store_group_t group;
    const char *pattern;
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
        if (!ctx->inspect(ctx->baton, name, ctx->vtype, value)) {
            return APR_EOF;
        }
    }
    return rv;
}

static apr_status_t fs_iterate(md_store_inspect *inspect, void *baton, md_store_t *store, 
                               md_store_group_t group, const char *pattern, md_store_vtype_t vtype)
{
    const char *filename, *groupname;
    apr_status_t rv;
    inspect_ctx ctx;
    
    ctx.s_fs = FS_STORE(store);
    ctx.group = group;
    ctx.pattern = pattern;
    ctx.vtype = vtype;
    ctx.inspect = inspect;
    ctx.baton = baton;
    
    groupname = sgroup_filename(group);
    filename = vtype_filename(vtype);
    
    rv = md_util_files_do(insp, &ctx, ctx.s_fs->p, ctx.s_fs->base, 
                          groupname, ctx.pattern, filename, NULL);
    
    return rv;
}
