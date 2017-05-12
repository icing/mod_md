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
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_file_io.h>
#include <apr_strings.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "md_crypt.h"
#include "md_util.h"

static int initialized;

struct md_pkey {
    EVP_PKEY   *pkey;
    apr_pool_t *pool;
};

apr_status_t md_crypt_init(apr_pool_t *pool)
{
    char seed[64];
    (void)pool;

    if (!initialized) {
        ERR_load_crypto_strings();
    
        while (!RAND_status()) {
            arc4random_buf(seed, sizeof(seed));
            RAND_seed(seed, sizeof(seed));
	}

        initialized = 1;
    }
    return APR_SUCCESS;
}

static apr_status_t make_pkey(md_pkey **ppkey, apr_pool_t *p) 
{
    md_pkey *pkey = apr_pcalloc(p, sizeof(*pkey));
    if (!pkey) {
        return APR_ENOMEM;
    }
    pkey->pool = p;
    *ppkey = pkey;
    return APR_SUCCESS;
}

void md_crypt_pkey_free(md_pkey *pkey)
{
    if (pkey->pkey) {
        EVP_PKEY_free(pkey->pkey);
        pkey->pkey = NULL;
    }
    
}

apr_status_t md_crypt_pkey_load(md_pkey **ppkey, apr_pool_t *p, const char *fname)
{
    FILE *f;
    apr_status_t status;
    
    if (make_pkey(ppkey, p) != APR_SUCCESS) {
        return APR_ENOMEM;
    }
    
    status = md_util_fopen(&f, fname, "r");
    if (status == APR_SUCCESS) {
        status = APR_EINVAL;
        (*ppkey)->pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        if ((*ppkey)->pkey != NULL) {
            status = APR_SUCCESS;
        }
        fclose(f);
    }

    if (status != APR_SUCCESS) {
        *ppkey = NULL;
    }
    return status;
}

apr_status_t md_crypt_pkey_load_rsa(md_pkey **ppkey, apr_pool_t *p, const char *fname)
{
    apr_status_t status;
    
    if ((status = md_crypt_pkey_load(ppkey, p, fname)) == APR_SUCCESS) {
        if (EVP_PKEY_id((*ppkey)->pkey) != EVP_PKEY_RSA) {
            md_crypt_pkey_free(*ppkey);
            *ppkey = NULL;
            status = APR_EINVAL;
        }
    }
    return status;
}

apr_status_t md_crypt_pkey_save(md_pkey *pkey, apr_pool_t *p, const char *fname)
{
    FILE *f;
    apr_status_t status;
    
    status = md_util_fopen(&f, fname, "w");
    if (status == APR_SUCCESS) {
        status = apr_file_perms_set(fname, (APR_FPROT_UREAD|APR_FPROT_UWRITE));
        if (status == APR_SUCCESS) {
            if (PEM_write_PrivateKey(f, pkey->pkey, NULL, NULL, 0, NULL, NULL) < 0) {
                status = APR_EGENERAL;
            }
        }
        else if (status == APR_ENOTIMPL) {
            /* TODO: Windows, OS2 do not implement this. Do we have other
             * means to secure the file? */
            if (PEM_write_PrivateKey(f, pkey->pkey, NULL, NULL, 0, NULL, NULL) < 0) {
                status = APR_EGENERAL;
            }
        }
        
        fclose(f);
    }
    return status;
}

apr_status_t md_crypt_pkey_gen_rsa(md_pkey **ppkey, apr_pool_t *p, int bits)
{
    EVP_PKEY_CTX *ctx = NULL;
    apr_status_t status;
    
    if (make_pkey(ppkey, p) != APR_SUCCESS) {
        return APR_ENOMEM;
    }
    
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx 
        && EVP_PKEY_keygen_init(ctx) >= 0
        && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) >= 0
        && EVP_PKEY_keygen(ctx, &(*ppkey)->pkey) >= 0) {
        status = APR_SUCCESS;
    }
    else {
        *ppkey = NULL;
        status = APR_EGENERAL;
    }
    
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return status;
}
