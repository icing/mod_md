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

#ifndef mod_md_md_store_h
#define mod_md_md_store_h

struct apr_array_header_t;
struct md_cert;
struct md_pkey;
struct md_t;

typedef struct md_store_t md_store_t;

typedef void md_store_destroy_cb(md_store_t *store);

typedef apr_status_t md_store_load_cb(md_store_t *store, 
                                      struct apr_array_header_t *mds, apr_pool_t *p);
typedef apr_status_t md_store_save_cb(md_store_t *store, struct apr_array_header_t *mds);

typedef apr_status_t md_store_load_md_cb(struct md_t **pmd, md_store_t *store, 
                                         const char *name, apr_pool_t *p);
typedef apr_status_t md_store_save_md_cb(md_store_t *store, struct md_t *md, int create);
typedef apr_status_t md_store_remove_md_cb(md_store_t *store, const char *name, int force);

typedef apr_status_t md_store_load_cert_cb(struct md_cert **pcert, md_store_t *store, 
                                           const char *name, apr_pool_t *p);
typedef apr_status_t md_store_save_cert_cb(md_store_t *store, const char *name, 
                                           struct md_cert *cert, int create);

typedef apr_status_t md_store_load_pkey_cb(struct md_pkey **ppkey, md_store_t *store, 
                                           const char *name, apr_pool_t *p);
typedef apr_status_t md_store_save_pkey_cb(md_store_t *store, const char *name,
                                           struct md_pkey *pkey, int create);

struct md_store_t {
    apr_pool_t *p;
    md_store_destroy_cb *destroy;

    md_store_save_cb *save;
    md_store_load_cb *load;

    md_store_load_md_cb *load_md;
    md_store_save_md_cb *save_md;
    md_store_remove_md_cb *remove_md;

    md_store_load_cert_cb *load_cert;
    md_store_save_cert_cb *save_cert;

    md_store_load_pkey_cb *load_pkey;
    md_store_save_pkey_cb *save_pkey;
};

void md_store_destroy(md_store_t *store);

apr_status_t md_store_load(md_store_t *store, struct apr_array_header_t *mds, apr_pool_t *p);
apr_status_t md_store_save(md_store_t *store, struct apr_array_header_t *mds);

apr_status_t md_store_load_md(struct md_t **pmd, md_store_t *store, 
                              const char *name, apr_pool_t *p);
apr_status_t md_store_save_md(md_store_t *store, struct md_t *md, int create);
apr_status_t md_store_remove_md(md_store_t *store, const char *name, int force);

apr_status_t md_store_load_cert(struct md_cert **pcert, md_store_t *store, 
                                const char *name, apr_pool_t *p);
apr_status_t md_store_save_cert(md_store_t *store, const char *name,
                                           struct md_cert *cert, int create);

apr_status_t md_store_load_pkey(struct md_pkey **ppkey, md_store_t *store, 
                                const char *name, apr_pool_t *p);
apr_status_t md_store_save_pkey(md_store_t *store, const char *name,
                                struct md_pkey *pkey, int create);

/**************************************************************************************************/
/* file system based store */

apr_status_t md_store_fs_init(md_store_t **pstore, apr_pool_t *p, const char *path);

#endif /* mod_md_md_store_h */
