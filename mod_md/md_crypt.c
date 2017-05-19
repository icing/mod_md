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
#include "md_log.h"
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
    
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, pool, "initializing RAND"); 
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
    apr_status_t rv;
    
    if (make_pkey(ppkey, p) != APR_SUCCESS) {
        return APR_ENOMEM;
    }
    
    rv = md_util_fopen(&f, fname, "r");
    if (rv == APR_SUCCESS) {
        rv = APR_EINVAL;
        (*ppkey)->pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        if ((*ppkey)->pkey != NULL) {
            rv = APR_SUCCESS;
        }
        fclose(f);
    }

    if (rv != APR_SUCCESS) {
        *ppkey = NULL;
    }
    return rv;
}

apr_status_t md_crypt_pkey_load_rsa(md_pkey **ppkey, apr_pool_t *p, const char *fname)
{
    apr_status_t rv;
    
    if ((rv = md_crypt_pkey_load(ppkey, p, fname)) == APR_SUCCESS) {
        if (EVP_PKEY_id((*ppkey)->pkey) != EVP_PKEY_RSA) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "key is not RSA: %s", fname); 
            md_crypt_pkey_free(*ppkey);
            *ppkey = NULL;
            rv = APR_EINVAL;
        }
    }
    return rv;
}

apr_status_t md_crypt_pkey_save(md_pkey *pkey, apr_pool_t *p, const char *fname)
{
    FILE *f;
    apr_status_t rv;
    
    rv = md_util_fopen(&f, fname, "w");
    if (rv == APR_SUCCESS) {
        rv = apr_file_perms_set(fname, MD_FPROT_F_UONLY);
        if (rv == APR_ENOTIMPL) {
            /* TODO: Windows, OS2 do not implement this. Do we have other
             * means to secure the file? */
            rv = APR_SUCCESS;
        }

        if (rv == APR_SUCCESS) {
            if (PEM_write_PrivateKey(f, pkey->pkey, NULL, NULL, 0, NULL, NULL) < 0) {
                md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "error writing key: %s", fname); 
                rv = APR_EGENERAL;
            }
        }
        
        fclose(f);
    }
    return rv;
}

apr_status_t md_crypt_pkey_gen_rsa(md_pkey **ppkey, apr_pool_t *p, int bits)
{
    EVP_PKEY_CTX *ctx = NULL;
    apr_status_t rv;
    
    if (make_pkey(ppkey, p) != APR_SUCCESS) {
        return APR_ENOMEM;
    }
    
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx 
        && EVP_PKEY_keygen_init(ctx) >= 0
        && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) >= 0
        && EVP_PKEY_keygen(ctx, &(*ppkey)->pkey) >= 0) {
        rv = APR_SUCCESS;
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "unable to generate new key"); 
        *ppkey = NULL;
        rv = APR_EGENERAL;
    }
    
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return rv;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void RSA_get0_key(const RSA *r,
                         const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

#endif

static const char *bn64(const BIGNUM *b, apr_pool_t *p) 
{
    if (b) {
         int len = BN_num_bytes(b);
         char *buffer = apr_pcalloc(p, len);
         if (buffer) {
            BN_bn2bin(b, (unsigned char *)buffer);
            return md_util_base64url_encode(buffer, len, p);
         }
    }
    return NULL;
}

const char *md_crypt_pkey_get_rsa_e64(md_pkey *pkey, apr_pool_t *p)
{
    const BIGNUM *e;
    RSA *rsa = EVP_PKEY_get1_RSA(pkey->pkey);
    
    if (!rsa) {
        return NULL;
    }
    RSA_get0_key(rsa, NULL, &e, NULL);
    return bn64(e, p);
}

const char *md_crypt_pkey_get_rsa_n64(md_pkey *pkey, apr_pool_t *p)
{
    const BIGNUM *n;
    RSA *rsa = EVP_PKEY_get1_RSA(pkey->pkey);
    
    if (!rsa) {
        return NULL;
    }
    RSA_get0_key(rsa, &n, NULL, NULL);
    return bn64(n, p);
}

apr_status_t md_crypt_sign64(const char **psign64, md_pkey *pkey, apr_pool_t *p, 
                             const char *d, size_t dlen)
{
    EVP_MD_CTX *ctx = NULL;
    char *buffer;
    unsigned int blen;
    const char *sign64 = NULL;
    apr_status_t rv = APR_ENOMEM;
    
    buffer = apr_pcalloc(p, EVP_PKEY_size(pkey->pkey));
    if (buffer) {
        ctx = EVP_MD_CTX_create();
        if (ctx) {
            rv = APR_ENOTIMPL;
            if (EVP_SignInit_ex(ctx, EVP_sha256(), NULL)) {
                rv = APR_EGENERAL;
                if (EVP_SignUpdate(ctx, d, dlen)) {
                    if (EVP_SignFinal(ctx, (unsigned char*)buffer, &blen, pkey->pkey)) {
                        sign64 = md_util_base64url_encode(buffer, blen, p);
                        if (sign64) {
                            rv = APR_SUCCESS;
                        }
                    }
                }
            }
        }
        
        if (ctx) {
            EVP_MD_CTX_destroy(ctx);
        }
    }
    
    if (rv != APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "signing"); 
    }
    
    *psign64 = sign64;
    return rv;
}

