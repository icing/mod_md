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

#ifndef mod_md_md_reg_h
#define mod_md_md_reg_h

struct apr_hash_t;
struct md_store;

/**
 * A registry for managed domains with a md_store_t as persistence.
 *
 */
typedef struct md_reg_t md_reg_t;

struct md_reg_t {
    apr_pool_t *p;
    struct md_store_t *store;
    struct apr_hash_t *mds;
};

/**
 * Initialize the registry, using the pool and loading any existing information
 * from the store.
 */
apr_status_t md_reg_init(md_reg_t **preg, apr_pool_t *pm, struct md_store_t *store);

/**
 * Add a new md to the registry. This will check the name for uniqueness and
 * that domain names do not overlap with already existing mds.
 */
apr_status_t md_reg_add(md_reg_t *reg, md_t *md);

/**
 * Find the md, if any, that contains the given domain name. 
 * NULL if none found.
 */
const md_t *md_reg_find(const md_reg_t *reg, const char *domain);

/**
 * Find one md, which domain names overlap with the given md and that has a different
 * name. There may be more than one existing md that overlaps. It is not defined
 * which one will be returned. 
 */
const md_t *md_reg_find_overlap(const md_reg_t *reg, const md_t *md, const char **pdomain);

/**
 * Get the md with the given unique name. NULL if it does not exist.
 */
const md_t *md_reg_get(const md_reg_t *reg, const char *name);

/**
 * Callback invoked for every md in the registry. If 0 is returned, iteration stops.
 */
typedef int md_reg_do_cb(void *baton, const md_reg_t *reg, const md_t *md);

/**
 * Invoke callback for all mds in this registry. Order is not guarantueed.
 * If the callback returns 0, iteration stops. Returns 0 if iteration was
 * aborted.
 */
int md_reg_do(md_reg_do_cb *cb, void *baton, const md_reg_t *reg);

/**
 * Bitmask for fields that are updated.
 */
#define MD_UPD_DOMAINS      0x0001
#define MD_UPD_CA_URL       0x0002
#define MD_UPD_CA_PROTO     0x0004

/**
 * Update the given fields for the managed domain. Take the new
 * values from the given md, all other values remain unchanged.
 */
apr_status_t md_reg_update(md_reg_t *reg, const char *name, const md_t *md, int fields);

#endif /* mod_md_md_reg_h */
