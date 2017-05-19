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

struct md_json;
struct md_pkey;

/** 
 * An ACME account at an ACME server.
 */
typedef struct md_acme_acct md_acme_acct;

struct md_acme_acct {
    const char *name;               /* short name unique for a server, file name compat */
    md_acme * acme;                 /* server this account is from */
    apr_pool_t *pool;               /* pool used for account data */

    const char *url;                /* url of the accunt, once registered */
    apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */

    struct md_pkey *key;            /* private key of account for JWS */
    
    struct md_json *registration;   /* data from server registration */
};

/**
 * Register a new account at the ACME server.
 *
 * @param pacct  will be assigned the new account on success
 * @param acme   the acme server to register at
 * @param contacts list of contact uris, at least one
 */
apr_status_t md_acme_register(struct md_acme_acct **pacct, md_acme *acme, 
                              apr_array_header_t *contacts);

/**
 * Unregister/delete the account at the ACME server. Will remove
 * local copy on success as well.
 *
 * @param acme    the ACME server to remove the account from
 * @param acct    the account to delete
 */
apr_status_t md_acme_acct_del(md_acme *acme, md_acme_acct *acct);

/**
 * Retrieve an existing account from the ACME server.
 * 
 * @param acme     the ACME server to get the account from
 * @param url      the url at which the account was registered or the name of the account
 */
md_acme_acct *md_acme_acct_get(md_acme *acme, const char *s);

/**
 * Load the accounts store for the ACME server. Only accounts registered
 * with the same server before will be found.
 * 
 * @param acme     the ACME server to load accounts for. 
 */
apr_status_t md_acme_acct_load(md_acme *acme);



#endif /* md_acme_acct_h */
