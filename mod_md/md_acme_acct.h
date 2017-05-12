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


typedef struct md_acme_acct md_acme_acct;

struct md_acme_acct {
    const char *key_file;
    void *key;
};

apr_status_t md_acme_acct_create(md_acme_acct **pacct, apr_pool_t *p, 
                                 const char *key_file, int key_bits);

apr_status_t md_acme_acct_open(md_acme_acct **pacct, apr_pool_t *p, const char *key_file);

#endif /* md_acme_acct_h */
