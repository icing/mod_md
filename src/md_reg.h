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
struct apr_array_header_t;
struct md_store_t;
struct md_pkey_t;
struct md_cert_t;
struct X509;

/**
 * A registry for managed domains with a md_store_t as persistence.
 *
 */
typedef struct md_reg_t md_reg_t;

/**
 * Initialize the registry, using the pool and loading any existing information
 * from the store.
 */
apr_status_t md_reg_init(md_reg_t **preg, apr_pool_t *pm, struct md_store_t *store);

struct md_store_t *md_reg_store_get(md_reg_t *reg);

/**
 * Add a new md to the registry. This will check the name for uniqueness and
 * that domain names do not overlap with already existing mds.
 */
apr_status_t md_reg_add(md_reg_t *reg, md_t *md);

/**
 * Find the md, if any, that contains the given domain name. 
 * NULL if none found.
 */
const md_t *md_reg_find(md_reg_t *reg, const char *domain, apr_pool_t *p);

/**
 * Find one md, which domain names overlap with the given md and that has a different
 * name. There may be more than one existing md that overlaps. It is not defined
 * which one will be returned. 
 */
const md_t *md_reg_find_overlap(md_reg_t *reg, const md_t *md, const char **pdomain, apr_pool_t *p);

/**
 * Get the md with the given unique name. NULL if it does not exist.
 */
const md_t *md_reg_get(md_reg_t *reg, const char *name, apr_pool_t *p);

/**
 * Callback invoked for every md in the registry. If 0 is returned, iteration stops.
 */
typedef int md_reg_do_cb(void *baton, md_reg_t *reg, const md_t *md);

/**
 * Invoke callback for all mds in this registry. Order is not guarantueed.
 * If the callback returns 0, iteration stops. Returns 0 if iteration was
 * aborted.
 */
int md_reg_do(md_reg_do_cb *cb, void *baton, md_reg_t *reg);

/**
 * Bitmask for fields that are updated.
 */
#define MD_UPD_DOMAINS      0x0001
#define MD_UPD_CA_URL       0x0002
#define MD_UPD_CA_PROTO     0x0004
#define MD_UPD_CA_ACCOUNT   0x0008
#define MD_UPD_CONTACTS     0x0010
#define MD_UPD_AGREEMENT    0x0020
#define MD_UPD_CERT_URL     0x0040
#define MD_UPD_ALL          0x7FFF

/**
 * Update the given fields for the managed domain. Take the new
 * values from the given md, all other values remain unchanged.
 */
apr_status_t md_reg_update(md_reg_t *reg, const char *name, const md_t *md, int fields);

/**
 * Initialize the state of the md (again), based on current properties and current
 * state of the store.
 */
apr_status_t md_reg_state_init(md_reg_t *reg, const md_t *md);

/**
 * Initialize all mds (again), based on current properties and current
 * state of the store.
 */
apr_status_t md_reg_states_init(md_reg_t *reg, int fail_early);

/**
 * Get the credentials available for the managed domain md. Returns APR_ENOENT
 * when none is available. The returned values are immutable. 
 */
apr_status_t md_reg_creds_get(const md_creds_t **pcreds, md_reg_t *reg, const md_t *md);

/**************************************************************************************************/
/* protocol drivers */

typedef struct md_proto_t md_proto_t;

typedef struct md_proto_driver_t md_proto_driver_t;

struct md_proto_driver_t {
    const md_proto_t *proto;
    apr_pool_t *p;
    struct md_store_t *store;
    md_reg_t *reg;
    const md_t *md;
    void *baton;
    int reset;
};

typedef apr_status_t md_proto_driver_init_cb(md_proto_driver_t *driver);
typedef apr_status_t md_proto_driver_run_cb(md_proto_driver_t *driver);

struct md_proto_t {
    const char *protocol;
    md_proto_driver_init_cb *init;
    md_proto_driver_run_cb *run;
};


/**
 * Drive the given managed domain toward completeness, if possible.
 */
apr_status_t md_reg_drive(md_reg_t *reg, const md_t *md, int reset, apr_pool_t *p);

#endif /* mod_md_md_reg_h */
