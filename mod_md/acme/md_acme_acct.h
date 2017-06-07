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

#ifndef mod_md_md_acme_acct_h
#define mod_md_md_acme_acct_h

struct md_acme_req;
struct md_json_t;
struct md_pkey_t;
struct md_store_t;

/** 
 * An ACME account at an ACME server.
 */
typedef struct md_acme_acct_t md_acme_acct_t;

struct md_acme_acct_t {
    const char *id;                 /* short, unique id for the account */
    struct md_store_t *store;       /* store this account was loaded from/saved in */
    apr_pool_t *pool;               /* pool used for account data */

    const char *ca_url;             /* url of the ACME protocol endpoint */
    const char *url;                /* url of the accunt, once registered */
    apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */
    const char *tos_required;       /* terms of service asked for by CA */
    const char *tos_agreed;         /* terms of service accepted by user */
    
    struct md_pkey_t *key;          /* private key of account for JWS */
    int key_changed;                /* key was changed, needs save */
    
    struct md_json_t *registration; /* data from server registration */
    int disabled;
};

/**
 * Register a new account at the ACME server.
 *
 * @param pacct  will be assigned the new account on success
 * @param acme   the acme server to register at
 * @param contacts list of contact uris, at least one
 */
apr_status_t md_acme_register(md_acme_acct_t **pacct, struct md_store_t *store, md_acme_t *acme, 
                              apr_array_header_t *contacts, const char *agreed_tos);

apr_status_t md_acme_acct_validate(md_acme_t *acme, md_acme_acct_t *acct);

apr_status_t md_acme_acct_agree_tos(md_acme_t *acme, md_acme_acct_t *acct, const char *tos);

/**
 * Unregister/delete the account at the ACME server. Will remove
 * local copy on success as well.
 *
 * @param acme    the ACME server to remove the account from
 * @param acct    the account to delete
 */
apr_status_t md_acme_acct_del(md_acme_acct_t *acct);

apr_status_t md_acme_acct_disable(md_acme_acct_t *acct);

apr_status_t md_acme_acct_load(md_acme_acct_t **pacct, 
                               struct md_store_t *store, const char *name, apr_pool_t *p);

/**
 * Find an ACME account for the given ACME service.
 */
apr_status_t md_acme_acct_find(md_acme_acct_t **pacct, 
                               struct md_store_t *store, md_acme_t *acme, apr_pool_t *p);

#endif /* md_acme_acct_h */
