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

typedef struct md_acme_acct md_acme_acct;

struct md_acme_acct {
    const char *name;
    apr_pool_t *pool;

    const char *url;
    apr_array_header_t *contacts;

    struct md_pkey *key;
    const char *key_file;
    
    struct md_json *registration;
};

apr_status_t md_acme_acct_create(md_acme_acct **pacct, apr_pool_t *p, 
                                 apr_array_header_t *contact, int key_bits);
void md_acme_acct_free(md_acme_acct *acct);

apr_status_t md_acme_acct_new(md_acme_acct **pacct, md_acme *acme,
                              struct apr_array_header_t *contacts);

apr_status_t md_acme_acct_load(md_acme_acct **pacct, md_acme *acme, const char *name);
apr_status_t md_acme_acct_save(md_acme_acct *acct, md_acme *acme);

apr_status_t md_acme_acct_del(md_acme *acme, md_acme_acct *acct);


apr_status_t md_acme_acct_scan(md_acme *acme, const char *path);

#endif /* md_acme_acct_h */
