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

#ifndef mod_md_md_h
#define mod_md_md_h

#define MD_PROTO_ACME       "ACME"

struct apr_hash_t;
struct md_pkey;
struct X509;

typedef enum {
    MD_S_INCOMPLETE,                /* MD is missing data, e.g. certificates */
    MD_S_COMPLETE,                  /* MD has all data, can go live */
    MD_S_EXPIRED,                   /* MD has all data, but (part of) is expired */
} md_state_t;

typedef struct md_t md_t;
struct md_t {
    const char         *name;       /* unique name of this MD */
    apr_array_header_t *domains;    /* all DNS names this MD includes */
    const char *ca_url;             /* url of CA certificate service */
    const char *ca_proto;           /* protocol used vs CA (e.g. ACME) */
    md_state_t state;               /* state of this MD */

    const char *defn_name;          /* config file this MD was defined */
    unsigned defn_line_number;      /* line number of definition */
    
    struct md_pkey *pkey;
    struct X509 *cert;
    apr_array_header_t *chain;      /* list of X509* */
};

#define MD_KEY_CA       "ca"
#define MD_KEY_DOMAINS  "domains"
#define MD_KEY_NAME     "name"
#define MD_KEY_PROTO    "proto"
#define MD_KEY_URL      "url"

/**
 * Determine if the Managed Domain contains a specific domain name.
 */
int md_contains(const md_t *md, const char *domain);

/**
 * Determine if the names of the two managed domains overlap.
 */
int md_names_overlap(const md_t *md1, const md_t *md2);

/**
 * Get one common domain name of the two managed domains or NULL.
 */
const char *md_common_name(const md_t *md1, const md_t *md2);

/**
 * Create and empty md record, structures initialized.
 */
md_t *md_create_empty(apr_pool_t *p);

/**
 * Create a managed domain, given a list of domain names.
 */
const char *md_create(md_t **pmd, apr_pool_t *p, int argc, char *const *argv);

md_t *md_clone(apr_pool_t *p, md_t *src);

typedef struct md_reg md_reg;
struct md_reg {
    apr_pool_t *p;
    struct apr_hash_t *mds;
    struct apr_hash_t *cas;
};

apr_status_t md_reg_init(apr_pool_t *p);

apr_status_t md_reg_add(md_reg *reg, md_t *md);

md_t *md_reg_find(md_reg *reg, const char *domain);

md_t *md_reg_get(md_reg *reg, const char *name);

typedef int md_reg_do_cb(void *baton, md_reg *reg, md_t *md);

apr_status_t md_reg_do(md_reg_do_cb *cb, void *baton, md_reg *reg);

#endif /* mod_md_md_h */
