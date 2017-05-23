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

apr_status_t md_store_load(md_store_t *store, apr_hash_t *mds)
{
    return store->load(store, mds);
}

apr_status_t md_store_save(md_store_t *store, apr_hash_t *mds)
{
    return store->save(store, mds);
}

apr_status_t md_store_load_md(md_store_t *store, md_t **pmd, const char *name)
{
    return store->load_md(store, pmd, name);
}

apr_status_t md_store_save_md(md_store_t *store, md_t *md)
{
    return store->save_md(store, md);
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

#define FS_DN_DOMAINS      "domains"
#define FS_FN_MD_JSON      "md.json"

static void fs_destroy(md_store_t *store);
static apr_status_t fs_load(md_store_t *store, apr_hash_t *mds);
static apr_status_t fs_save(md_store_t *store, apr_hash_t *mds);
static apr_status_t fs_load_md(md_store_t *store, md_t **pmd, const char *name);
static apr_status_t fs_save_md(md_store_t *store, md_t *md);

apr_status_t md_store_fs_init(md_store_t **pstore, apr_pool_t *p, const char *path)
{
    md_store_fs_t *s_fs;
    apr_status_t rv = APR_ENOMEM;
    
    s_fs = apr_pcalloc(p, sizeof(*s_fs));
    if (s_fs) {
        s_fs->p = s_fs->s.p = p;
        s_fs->s.destroy = fs_destroy;
        s_fs->s.load = fs_load;
        s_fs->s.save = fs_save;
        s_fs->s.load_md = fs_load_md;
        s_fs->s.save_md = fs_save_md;
        
        if (NULL == (s_fs->base = apr_pstrdup(p, path)) 
            || APR_SUCCESS != (rv = md_util_is_dir(s_fs->base, p))) {
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

static apr_status_t pfs_load_md(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *fpath, *name;
    md_t **pmd, *md = NULL;
    apr_status_t rv;
    
    pmd = va_arg(ap, md_t **);
    name = va_arg(ap, const char *);
    rv = md_util_path_merge(&fpath, ptemp, s_fs->base, FS_DN_DOMAINS, name, FS_FN_MD_JSON, NULL);
    if (APR_SUCCESS == rv) {
        md_json *json;
        
        rv = md_json_readf(&json, ptemp, fpath);
        if (APR_SUCCESS == rv) {
            md_t *md = md_create_empty(p); /* from outside pool */
            if (md) {
                md->name = apr_pstrdup(p, name);
                md->defn_name = apr_pstrdup(p, fpath);
                
                md_json_getsa(md->domains, json, MD_KEY_DOMAINS, NULL);
                md->ca_proto = md_json_gets(json, MD_KEY_CA, MD_KEY_PROTO, NULL);
                md->ca_url = md_json_gets(json, MD_KEY_CA, MD_KEY_URL, NULL);
            }
        }
    }
    *pmd = (APR_SUCCESS == rv)? md : NULL;
    return rv;
}

static apr_status_t pfs_save_md(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *fpath;
    md_t *md;
    apr_status_t rv;
    
    md = va_arg(ap, md_t *);
    rv = md_util_path_merge(&fpath, ptemp, s_fs->base, FS_DN_DOMAINS, md->name, NULL);
    if (APR_SUCCESS == rv) {
        if (APR_SUCCESS == (rv = apr_dir_make_recursive(fpath, MD_FPROT_D_UONLY, ptemp))) {
            md_json *json = md_json_create(ptemp);
            
            md_json_sets(md->name, json, MD_KEY_NAME, NULL);
            md_json_setsa(md->domains, json, MD_KEY_DOMAINS, NULL);
            md_json_sets(md->ca_proto, json, MD_KEY_CA, MD_KEY_PROTO, NULL);
            md_json_sets(md->ca_url, json, MD_KEY_CA, MD_KEY_URL, NULL);
            
            rv = md_json_freplace(json, ptemp, fpath, FS_FN_MD_JSON);
        }
    }
    return rv;
}

static apr_status_t fs_load(md_store_t *store, apr_hash_t *mds)
{
    return APR_ENOTIMPL;
}

static apr_status_t fs_save(md_store_t *store, apr_hash_t *mds)
{
    return APR_ENOTIMPL;
}

static apr_status_t fs_load_md(md_store_t *store, md_t **pmd, const char *name)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_load_md, s_fs, s_fs->p, pmd, name, NULL);
}

static apr_status_t fs_save_md(md_store_t *store, md_t *md)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_save_md, s_fs, s_fs->p, md, NULL);
}
