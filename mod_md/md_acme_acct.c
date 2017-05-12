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

#include <stdio.h>
#include <apr_lib.h>
#include <apr_strings.h>

#include "md_acme_acct.h"
#include "md_crypt.h"

static apr_status_t acct_make(md_acme_acct **pacct, apr_pool_t *p, void *pkey, const char *key_file)
{
    md_acme_acct *acct;
    
    acct = apr_pcalloc(p, sizeof(*acct));
    if (!acct) {
        if (pkey) {
            md_crypt_pkey_free(pkey);
        }
        return APR_ENOMEM;
    }
    
    acct->key_file = key_file;
    acct->key = pkey;
    
    *pacct = acct;
    return APR_SUCCESS;
}


apr_status_t md_acme_acct_create(md_acme_acct **pacct, apr_pool_t *p, const char *key_file,
    int key_bits)
{
    apr_status_t status;
    md_pkey *pkey;
    
    status = md_crypt_pkey_gen_rsa(&pkey, p, key_bits);
    if (status == APR_SUCCESS) {
        status = acct_make(pacct, p, pkey, key_file);
    }
    return status;
}

apr_status_t md_acme_acct_open(md_acme_acct **pacct, apr_pool_t *p, const char *key_file)
{
    apr_status_t status;
    md_pkey *pkey;
    
    status = md_crypt_pkey_load_rsa(&pkey, p, key_file);
    if (status == APR_SUCCESS) {
        return acct_make(pacct, p, pkey, key_file);
    }
    return status;
}


