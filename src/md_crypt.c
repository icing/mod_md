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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_buckets.h>
#include <apr_file_io.h>
#include <apr_strings.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "md.h"
#include "md_crypt.h"
#include "md_log.h"
#include "md_http.h"
#include "md_util.h"

static int initialized;

struct md_pkey_t {
    apr_pool_t *pool;
    EVP_PKEY   *pkey;
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

/**************************************************************************************************/
/* private keys */

static md_pkey_t *make_pkey(apr_pool_t *p) 
{
    md_pkey_t *pkey = apr_pcalloc(p, sizeof(*pkey));
    pkey->pool = p;
    return pkey;
}

static apr_status_t pkey_cleanup(void *data)
{
    md_pkey_t *pkey = data;
    if (pkey->pkey) {
        EVP_PKEY_free(pkey->pkey);
        pkey->pkey = NULL;
    }
    return APR_SUCCESS;
}

void md_pkey_free(md_pkey_t *pkey)
{
    pkey_cleanup(pkey);
}

apr_status_t md_pkey_fload(md_pkey_t **ppkey, apr_pool_t *p, const char *fname)
{
    FILE *f;
    apr_status_t rv;
    md_pkey_t *pkey;
    
    pkey =  make_pkey(p);
    rv = md_util_fopen(&f, fname, "r");
    if (rv == APR_SUCCESS) {
        rv = APR_EINVAL;
        pkey->pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        if (pkey->pkey != NULL) {
            rv = APR_SUCCESS;
            apr_pool_cleanup_register(p, pkey, pkey_cleanup, apr_pool_cleanup_null);
        }
        fclose(f);
    }

    *ppkey = (APR_SUCCESS == rv)? pkey : NULL;
    return rv;
}

apr_status_t md_pkey_fload_rsa(md_pkey_t **ppkey, apr_pool_t *p, const char *fname)
{
    apr_status_t rv;
    
    if ((rv = md_pkey_fload(ppkey, p, fname)) == APR_SUCCESS) {
        if (EVP_PKEY_id((*ppkey)->pkey) != EVP_PKEY_RSA) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "key is not RSA: %s", fname); 
            md_pkey_free(*ppkey);
            *ppkey = NULL;
            rv = APR_EINVAL;
        }
    }
    return rv;
}

apr_status_t md_pkey_fsave(md_pkey_t *pkey, apr_pool_t *p, const char *fname)
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

apr_status_t md_pkey_gen_rsa(md_pkey_t **ppkey, apr_pool_t *p, int bits)
{
    EVP_PKEY_CTX *ctx = NULL;
    apr_status_t rv;
    
    *ppkey = make_pkey(p);
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

#ifndef NID_tlsfeature
#define NID_tlsfeature          1020
#endif

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

const char *md_pkey_get_rsa_e64(md_pkey_t *pkey, apr_pool_t *p)
{
    const BIGNUM *e;
    RSA *rsa = EVP_PKEY_get1_RSA(pkey->pkey);
    
    if (!rsa) {
        return NULL;
    }
    RSA_get0_key(rsa, NULL, &e, NULL);
    return bn64(e, p);
}

const char *md_pkey_get_rsa_n64(md_pkey_t *pkey, apr_pool_t *p)
{
    const BIGNUM *n;
    RSA *rsa = EVP_PKEY_get1_RSA(pkey->pkey);
    
    if (!rsa) {
        return NULL;
    }
    RSA_get0_key(rsa, &n, NULL, NULL);
    return bn64(n, p);
}

apr_status_t md_crypt_sign64(const char **psign64, md_pkey_t *pkey, apr_pool_t *p, 
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

apr_status_t md_crypt_sha256_digest64(const char **pdigest64, apr_pool_t *p, 
                                      const char *d, size_t dlen)
{
    EVP_MD_CTX *ctx = NULL;
    const char *digest64 = NULL;
    unsigned char *buffer;
    apr_status_t rv = APR_ENOMEM;
    unsigned int blen;
    
    buffer = apr_pcalloc(p, EVP_MAX_MD_SIZE);
    if (buffer) {
        ctx = EVP_MD_CTX_create();
        if (ctx) {
            rv = APR_ENOTIMPL;
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
                rv = APR_EGENERAL;
                if (EVP_DigestUpdate(ctx, d, dlen)) {
                    if (EVP_DigestFinal(ctx, buffer, &blen)) {
                        digest64 = md_util_base64url_encode((const char*)buffer, blen, p);
                        if (digest64) {
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
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "digest"); 
    }
    
    *pdigest64 = digest64;
    return rv;
}

/**************************************************************************************************/
/* certificates */

struct md_cert_t {
    apr_pool_t *pool;
    X509 *x509;
};

static apr_status_t cert_cleanup(void *data)
{
    md_cert_t *cert = data;
    if (cert->x509) {
        X509_free(cert->x509);
        cert->x509 = NULL;
    }
    return APR_SUCCESS;
}

static md_cert_t *make_cert(apr_pool_t *p, X509 *x509) 
{
    md_cert_t *cert = apr_pcalloc(p, sizeof(*cert));
    cert->pool = p;
    cert->x509 = x509;
    apr_pool_cleanup_register(p, cert, cert_cleanup, apr_pool_cleanup_null);
    
    return cert;
}

void md_cert_free(md_cert_t *cert)
{
    cert_cleanup(cert);
}

int md_cert_is_valid_now(md_cert_t *cert)
{
    return ((X509_cmp_current_time(X509_get_notBefore(cert->x509)) < 0)
            && (X509_cmp_current_time(X509_get_notAfter(cert->x509)) > 0));
}

int md_cert_has_expired(md_cert_t *cert)
{
    return (X509_cmp_current_time(X509_get_notAfter(cert->x509)) > 0);
}

apr_status_t md_cert_get_issuers_uri(const char **puri, md_cert_t *cert, apr_pool_t *p)
{
    int i, ext_idx, nid = NID_info_access;
    X509_EXTENSION *ext;
    X509V3_EXT_METHOD *ext_cls;
    void *ext_data;
    const char *uri = NULL;
    apr_status_t rv = APR_ENOENT;
    
    /* Waddle through x509  API history to get someone that may be able
     * to hand us the issuer url for the cert chain */
    ext_idx = X509_get_ext_by_NID(cert->x509, nid, -1);
    ext = (ext_idx >= 0)? X509_get_ext(cert->x509, ext_idx) : NULL;
    ext_cls = ext? (X509V3_EXT_METHOD*)X509V3_EXT_get(ext) : NULL;
    if (ext_cls && (ext_data = X509_get_ext_d2i(cert->x509, nid, 0, 0))) {
        CONF_VALUE *cval;
        STACK_OF(CONF_VALUE) *ext_vals = ext_cls->i2v(ext_cls, ext_data, 0);
        
        for (i = 0; i < sk_CONF_VALUE_num(ext_vals); ++i) {
            cval = sk_CONF_VALUE_value(ext_vals, i);
            if (!strcmp("CA Issuers - URI", cval->name)) {
                uri = apr_pstrdup(p, cval->value);
                rv = APR_SUCCESS;
                break;
            }
        }
    } 
    *puri = (APR_SUCCESS == rv)? uri : NULL;
    return rv;
}


apr_status_t md_cert_fload(md_cert_t **pcert, apr_pool_t *p, const char *fname)
{
    FILE *f;
    apr_status_t rv;
    md_cert_t *cert;
    X509 *x509;
    
    rv = md_util_fopen(&f, fname, "r");
    if (rv == APR_SUCCESS) {
    
        x509 = PEM_read_X509(f, NULL, NULL, NULL);
        rv = fclose(f);
        if (x509 != NULL) {
            cert =  make_cert(p, x509);
        }
        else {
            rv = APR_EINVAL;
        }
    }

    *pcert = (APR_SUCCESS == rv)? cert : NULL;
    return rv;
}


apr_status_t md_cert_fsave(md_cert_t *cert, apr_pool_t *p, const char *fname)
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
        ERR_clear_error();
        
        PEM_write_X509(f, cert->x509);
        rv = fclose(f);
        
        if (ERR_get_error() > 0) {
            rv = APR_EINVAL;
        }
    }
    return rv;
}

apr_status_t md_cert_read_http(md_cert_t **pcert, apr_pool_t *p, 
                               const md_http_response_t *res)
{
    const char *ct;
    apr_off_t data_len;
    apr_size_t der_len;
    apr_status_t rv;
    
    ct = apr_table_get(res->headers, "Content-Type");
    if (!res->body || !ct  || strcmp("application/pkix-cert", ct)) {
        return APR_ENOENT;
    }
    
    if (APR_SUCCESS == (rv = apr_brigade_length(res->body, 1, &data_len))) {
        char *der;
        if (data_len > 1024*1024) { /* certs usually are <2k each */
            return APR_EINVAL;
        }
        if (APR_SUCCESS == (rv = apr_brigade_pflatten(res->body, &der, &der_len, p))) {
            const unsigned char *bf = (const unsigned char*)der;
            X509 *x509;
            
            if (NULL == (x509 = d2i_X509(NULL, &bf, der_len))) {
                rv = APR_EINVAL;
            }
            else {
                *pcert = make_cert(p, x509);
                rv = APR_SUCCESS;
            }
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "cert parsed");
    }
    return rv;
}

md_cert_state_t md_cert_state_get(md_cert_t *cert)
{
    if (cert->x509) {
        return md_cert_is_valid_now(cert)? MD_CERT_VALID : MD_CERT_EXPIRED;
    }
    return MD_CERT_UNKNOWN;
}

apr_status_t md_chain_fload(apr_array_header_t **pcerts, apr_pool_t *p, const char *fname)
{
    FILE *f;
    apr_status_t rv;
    apr_array_header_t *certs;
    X509 *x509;
    md_cert_t *cert;
    unsigned long err;
    
    rv = md_util_fopen(&f, fname, "r");
    if (rv == APR_SUCCESS) {
        certs = apr_array_make(p, 5, sizeof(md_cert_t *));
        
        ERR_clear_error();
        while (NULL != (x509 = PEM_read_X509(f, NULL, NULL, NULL))) {
            cert = make_cert(p, x509);
            APR_ARRAY_PUSH(certs, md_cert_t *) = cert;
        }
        
        if (cert->x509 != NULL) {
            rv = APR_SUCCESS;
            apr_pool_cleanup_register(p, cert, cert_cleanup, apr_pool_cleanup_null);
        }
        rv = fclose(f);
        
        if (0 < (err =  ERR_get_error())
            && !(ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
            /* not the expected one when no more PEM encodings are found */
            rv = APR_EINVAL;
        }
    }
    *pcerts = (APR_SUCCESS == rv)? certs : NULL;
    return rv;
}

apr_status_t md_chain_fsave(apr_array_header_t *certs, apr_pool_t *p, const char *fname)
{
    FILE *f;
    apr_status_t rv;
    const md_cert_t *cert;
    unsigned long err = 0;
    int i;
    
    rv = md_util_fopen(&f, fname, "w");
    if (rv == APR_SUCCESS) {
        ERR_clear_error();
        for (i = 0; i < certs->nelts; ++i) {
            cert = APR_ARRAY_IDX(certs, i, const md_cert_t *);
            assert(cert->x509);
            
            PEM_write_X509(f, cert->x509);
            
            if (0 < (err = ERR_get_error())) {
                break;
            }
            
        }
        rv = fclose(f);
        if (err) {
            rv = APR_EINVAL;
        }
    }
    return rv;
}

/**************************************************************************************************/
/* certificate signing requests */

static apr_status_t add_alt_names(STACK_OF(X509_EXTENSION) *exts, const md_t *md, apr_pool_t *p)
{
    
    if (md->domains->nelts > 0) {
        const char *alt_names = "", *sep = "", *domain;
        X509_EXTENSION *x;
        int i;
        
        for (i = 0; i < md->domains->nelts; ++i) {
            domain = APR_ARRAY_IDX(md->domains, i, const char *);
            alt_names = apr_psprintf(p, "%s%sDNS:%s", alt_names, sep, domain);
            sep = ",";
        }
        
        if (NULL == (x = X509V3_EXT_conf_nid(NULL, NULL, 
                                             NID_subject_alt_name, (char*)alt_names))) {
            return APR_EGENERAL;
        }
        sk_X509_EXTENSION_push(exts, x);
    }
    return APR_SUCCESS;
}

static apr_status_t add_must_staple(STACK_OF(X509_EXTENSION) *exts, const md_t *md, apr_pool_t *p)
{
    
    if (md->must_staple) {
        X509_EXTENSION *x = X509V3_EXT_conf_nid(NULL, NULL, 
                                                NID_tlsfeature, (char*)"DER:30:03:02:01:05");
        if (NULL == x) {
            return APR_EGENERAL;
        }
        sk_X509_EXTENSION_push(exts, x);
    }
    return APR_SUCCESS;
}

apr_status_t md_cert_req_create(const char **pcsr_der_64, const md_t *md, 
                                md_pkey_t *pkey, apr_pool_t *p)
{
    const char *s, *csr_der, *csr_der_64 = NULL;
    const unsigned char *domain;
    X509_REQ *csr;
    X509_NAME *n = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    apr_status_t rv = APR_EGENERAL;
    int csr_der_len;
    
    assert(md->domains->nelts > 0);
    
    if (NULL == (csr = X509_REQ_new()) 
        || NULL == (exts = sk_X509_EXTENSION_new_null())
        || NULL == (n = X509_NAME_new())) {
        rv = APR_ENOMEM;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: openssl alloc X509 things", md->name);
        goto out; 
    }

    /* subject name == first domain */
    domain = APR_ARRAY_IDX(md->domains, 0, const unsigned char *);
    if (!X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, domain, -1, -1, 0)
        || !X509_REQ_set_subject_name(csr, n)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: REQ name add entry", md->name);
        goto out;
    }
    /* collect extensions, such as alt names and must staple */
    if (APR_SUCCESS != (rv = add_alt_names(exts, md, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: collecting alt names", md->name);
        goto out;
    }
    if (APR_SUCCESS != (rv = add_must_staple(exts, md, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: must staple", md->name);
        goto out;
    }
    /* add extensions to csr */
    if (sk_X509_EXTENSION_num(exts) > 0 && !X509_REQ_add_extensions(csr, exts)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: adding exts", md->name);
        goto out;
    }
    /* add our key */
    if (!X509_REQ_set_pubkey(csr, pkey->pkey)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set pkey in csr", md->name);
        goto out;
    }
    /* sign, der encode and base64url encode */
    if (!X509_REQ_sign(csr, pkey->pkey, EVP_sha256())) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: sign csr", md->name);
        goto out;
    }
    if ((csr_der_len = i2d_X509_REQ(csr, NULL)) < 0) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: der length", md->name);
        goto out;
    }
    s = csr_der = apr_pcalloc(p, csr_der_len + 1);
    if (i2d_X509_REQ(csr, (unsigned char**)&s) != csr_der_len) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: csr der enc", md->name);
        goto out;
    }
    csr_der_64 = md_util_base64url_encode(csr_der, csr_der_len, p);
    rv = APR_SUCCESS;
    
out:
    if (exts) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    if (csr) {
        X509_REQ_free(csr);
    }
    *pcsr_der_64 = (APR_SUCCESS == rv)? csr_der_64 : NULL;
    return rv;
}

