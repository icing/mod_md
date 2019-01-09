/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
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


/** 
 * An ACME account at an ACME server.
 */
typedef struct md_acme_acct_t md_acme_acct_t;

struct md_acme_acct_t {
    const char *id;                 /* short, unique id for the account */
    const char *url;                /* url of the account, once registered */
    const char *ca_url;             /* url of the ACME protocol endpoint */
    apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */
    const char *tos_required;       /* terms of service asked for by CA */
    const char *agreement;          /* terms of service agreed to by user */
    
    struct md_json_t *registration; /* data from server registration */
    int disabled;
};

#define MD_FN_ACCOUNT           "account.json"
#define MD_FN_ACCT_KEY          "account.pem"

/* ACME account private keys are always RSA and have that many bits. Since accounts
 * are expected to live long, better err on the safe side. */
#define MD_ACME_ACCT_PKEY_BITS  3072

#define MD_ACME_ACCT_STAGED     "staged"

apr_status_t md_acme_acct_load(struct md_acme_acct_t **pacct, struct md_pkey_t **ppkey,
                               struct md_store_t *store, md_store_group_t group, 
                               const char *name, apr_pool_t *p);

/** 
 * Specify the account to use by name in local store. On success, the account
 * the "current" one used by the acme instance.
 */
apr_status_t md_acme_use_acct(md_acme_t *acme, struct md_store_t *store, 
                              apr_pool_t *p, const char *acct_id);

apr_status_t md_acme_use_acct_staged(md_acme_t *acme, struct md_store_t *store, 
                                     md_t *md, apr_pool_t *p);

/**
 * Get the local name of the account currently used by the acme instance.
 * Will be NULL if no account has been setup successfully.
 */
const char *md_acme_get_acct_id(md_acme_t *acme);

/**
 * Agree to the given Terms-of-Service url for the current account.
 */
apr_status_t md_acme_agree(md_acme_t *acme, apr_pool_t *p, const char *tos);

/**
 * Confirm with the server that the current account agrees to the Terms-of-Service
 * given in the agreement url.
 * If the known agreement is equal to this, nothing is done.
 * If it differs, the account is re-validated in the hope that the server
 * announces the Tos URL it wants. If this is equal to the agreement specified,
 * the server is notified of this. If the server requires a ToS that the account
 * thinks it has already given, it is resend.
 *
 * If an agreement is required, different from the current one, APR_INCOMPLETE is
 * returned and the agreement url is returned in the parameter.
 */
apr_status_t md_acme_check_agreement(md_acme_t *acme, apr_pool_t *p, 
                                     const char *agreement, const char **prequired);

/**
 * Get the ToS agreement for current account.
 */
const char *md_acme_get_agreement(md_acme_t *acme);


/** 
 * Find an existing account in the local store. On APR_SUCCESS, the acme
 * instance will have a current, validated account to use.
 */ 
apr_status_t md_acme_find_acct(md_acme_t *acme, struct md_store_t *store, apr_pool_t *p);

/**
 * Create a new account at the ACME server. The
 * new account is the one used by the acme instance afterwards, on success.
 */
apr_status_t md_acme_create_acct(md_acme_t *acme, apr_pool_t *p, apr_array_header_t *contacts, 
                                 const char *agreement);

apr_status_t md_acme_acct_save(struct md_store_t *store, apr_pool_t *p, md_acme_t *acme,  
                               struct md_acme_acct_t *acct, struct md_pkey_t *acct_key);
                               
apr_status_t md_acme_save(md_acme_t *acme, struct md_store_t *store, apr_pool_t *p);

apr_status_t md_acme_acct_save_staged(md_acme_t *acme, struct md_store_t *store, 
                                      md_t *md, apr_pool_t *p);

/**
 * Delete the current account at the ACME server and remove it from store. 
 */
apr_status_t md_acme_delete_acct(md_acme_t *acme, struct md_store_t *store, apr_pool_t *p);

#endif /* md_acme_acct_h */
