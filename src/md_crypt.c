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

/* getpid for *NIX */
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* getpid for Windows */
#if APR_HAVE_PROCESS_H
#include <process.h>
#endif

static int initialized;

struct md_pkey_t {
    apr_pool_t *pool;
    EVP_PKEY   *pkey;
};

#ifdef MD_HAVE_ARC4RANDOM

static void seed_RAND(int pid)
{
    char seed[128];
    arc4random_buf(seed, sizeof(seed));
    RAND_seed(seed, sizeof(seed));
}

#else /* ifdef MD_HAVE_ARC4RANDOM */

static int rand_choosenum(int l, int h)
{
    int i;
    char buf[50];

    apr_snprintf(buf, sizeof(buf), "%.0f",
                 (((double)(rand()%RAND_MAX)/RAND_MAX)*(h-l)));
    i = atoi(buf)+1;
    if (i < l) i = l;
    if (i > h) i = h;
    return i;
}

static void seed_RAND(int pid)
{   
    unsigned char stackdata[256];
    /* stolen from mod_ssl/ssl_engine_rand.c */
    apr_size_t n, l;
    struct {
        time_t t;
        pid_t pid;
    } my_seed;
    
    /*
     * seed in the current time (usually just 4 bytes)
     */
    my_seed.t = time(NULL);
    
    /*
     * seed in the current process id (usually just 4 bytes)
     */
    my_seed.pid = pid;
    
    l = sizeof(my_seed);
    RAND_seed((unsigned char *)&my_seed, l);
    
    /*
     * seed in some current state of the run-time stack (128 bytes)
     */
#if HAVE_VALGRIND && 0
    if (ssl_running_on_valgrind) {
        VALGRIND_MAKE_MEM_DEFINED(stackdata, sizeof(stackdata));
    }
#endif
    n = rand_choosenum(0, sizeof(stackdata)-128-1);
    RAND_seed(stackdata+n, 128);
}

#endif /*ifdef MD_HAVE_ARC4RANDOM (else part) */


apr_status_t md_crypt_init(apr_pool_t *pool)
{
    (void)pool;
    
    if (!initialized) {
        int pid = getpid();
        
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, pool, "initializing RAND"); 
        while (!RAND_status()) {
            seed_RAND(pid);
	}

        initialized = 1;
    }
    return APR_SUCCESS;
}

typedef struct {
    char *data;
    apr_size_t len;
} buffer;

static apr_status_t fwrite_buffer(void *baton, apr_file_t *f, apr_pool_t *p) 
{
    buffer *buf = baton;
    return apr_file_write_full(f, buf->data, buf->len, &buf->len);
}

apr_status_t md_rand_bytes(const char *buf, apr_size_t len, apr_pool_t *p)
{
    apr_status_t rv;
    
    if (len > INT_MAX) {
        return APR_ENOTIMPL;
    }
    if (APR_SUCCESS == (rv = md_crypt_init(p))) {
        RAND_bytes((unsigned char*)buf, (int)len);
    }
    return rv;
}

typedef struct {
    const char *pass_phrase;
    int pass_len;
} passwd_ctx;

static int pem_passwd(char *buf, int size, int rwflag, void *baton)
{
    passwd_ctx *ctx = baton;
    if (ctx->pass_len > 0) {
        if (ctx->pass_len < size) {
            size = (int)ctx->pass_len;
        }
        memcpy(buf, ctx->pass_phrase, size);
    }
    return ctx->pass_len;
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

apr_status_t md_pkey_fload(md_pkey_t **ppkey, apr_pool_t *p, 
                           const char *key, apr_size_t key_len,
                           const char *fname)
{
    FILE *f;
    apr_status_t rv;
    md_pkey_t *pkey;
    passwd_ctx ctx;
    
    pkey =  make_pkey(p);
    rv = md_util_fopen(&f, fname, "r");
    if (rv == APR_SUCCESS) {
        rv = APR_EINVAL;
        if (key_len > INT_MAX) {
            goto out;
        }
        ctx.pass_phrase = key;
        ctx.pass_len = (int)key_len;
        pkey->pkey = PEM_read_PrivateKey(f, NULL, pem_passwd, &ctx);
        if (pkey->pkey != NULL) {
            rv = APR_SUCCESS;
            apr_pool_cleanup_register(p, pkey, pkey_cleanup, apr_pool_cleanup_null);
        }
        fclose(f);
    }
out:
    *ppkey = (APR_SUCCESS == rv)? pkey : NULL;
    return rv;
}

apr_status_t md_pkey_fload_rsa(md_pkey_t **ppkey, apr_pool_t *p, 
                               const char *pass_phrase, apr_size_t pass_len,
                               const char *fname)
{
    apr_status_t rv;
    
    if ((rv = md_pkey_fload(ppkey, p, pass_phrase, pass_len, fname)) == APR_SUCCESS) {
        if (EVP_PKEY_id((*ppkey)->pkey) != EVP_PKEY_RSA) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "key is not RSA: %s", fname); 
            md_pkey_free(*ppkey);
            *ppkey = NULL;
            rv = APR_EINVAL;
        }
    }
    return rv;
}

static apr_status_t pkey_to_buffer(buffer *buffer, md_pkey_t *pkey, apr_pool_t *p,
                                   const char *pass, apr_size_t pass_len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    const EVP_CIPHER *cipher = NULL;
    pem_password_cb *cb = NULL;
    void *cb_baton = NULL;
    passwd_ctx ctx;
    unsigned long err;
    
    if (!bio) {
        return APR_ENOMEM;
    }
    if (pass_len > INT_MAX) {
        return APR_EINVAL;
    }
    if (pass && pass_len > 0) {
        ctx.pass_phrase = pass;
        ctx.pass_len = (int)pass_len;
        cb = pem_passwd;
        cb_baton = &ctx;
        cipher = EVP_aes_256_cbc();
        if (!cipher) {
            return APR_ENOTIMPL;
        }
    }
    
    ERR_clear_error();
    if (!PEM_write_bio_PrivateKey(bio, pkey->pkey, cipher, NULL, 0, cb, cb_baton)) {
        BIO_free(bio);
        err = ERR_get_error();
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "PEM_write key: %ld %s", 
                      err, ERR_error_string(err, NULL)); 
        return APR_EINVAL;
    }

    buffer->len = BIO_pending(bio);
    if (buffer->len > 0) {
        buffer->data = apr_palloc(p, buffer->len+1);
        buffer->len = BIO_read(bio, buffer->data, (int)buffer->len);
        buffer->data[buffer->len] = '\0';
    }
    BIO_free(bio);
    return APR_SUCCESS;
}

apr_status_t md_pkey_fsave(md_pkey_t *pkey, apr_pool_t *p, 
                           const char *pass_phrase, apr_size_t pass_len,
                           const char *fname, apr_fileperms_t perms)
{
    buffer buffer;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = pkey_to_buffer(&buffer, pkey, p, pass_phrase, pass_len))) {
        return md_util_freplace(fname, perms, p, fwrite_buffer, &buffer); 
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "save pkey %s (%s pass phrase, len=%d)",
                  fname, pass_len > 0? "with" : "without", (int)pass_len); 
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
    apr_array_header_t *alt_names;
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

int md_cert_is_valid_now(const md_cert_t *cert)
{
    return ((X509_cmp_current_time(X509_get_notBefore(cert->x509)) < 0)
            && (X509_cmp_current_time(X509_get_notAfter(cert->x509)) > 0));
}

int md_cert_has_expired(const md_cert_t *cert)
{
    return (X509_cmp_current_time(X509_get_notAfter(cert->x509)) <= 0);
}

apr_time_t md_cert_get_not_after(md_cert_t *cert)
{
    int secs, days;
    apr_time_t time = apr_time_now();
    ASN1_TIME *not_after = X509_get_notAfter(cert->x509);
    
    if (ASN1_TIME_diff(&days, &secs, NULL, not_after)) {
        time += apr_time_from_sec((days * MD_SECS_PER_DAY) + secs); 
    }
    return time;
}

int md_cert_covers_md(md_cert_t *cert, const md_t *md)
{
    const char *name;
    int i;
    
    if (!cert->alt_names) {
        md_cert_get_alt_names(&cert->alt_names, cert, cert->pool);
    }
    if (cert->alt_names) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, cert->pool, "cert has %d alt names",
                      cert->alt_names->nelts); 
        for (i = 0; i < md->domains->nelts; ++i) {
            name = APR_ARRAY_IDX(md->domains, i, const char *);
            if (md_array_str_index(cert->alt_names, name, 0, 0) < 0) {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, cert->pool, 
                              "md domain %s not covered by cert", name);
                return 0;
            }
        }
        return 1;
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, cert->pool, "cert has NO alt names");
    }
    return 0;
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

apr_status_t md_cert_get_alt_names(apr_array_header_t **pnames, md_cert_t *cert, apr_pool_t *p)
{
    apr_array_header_t *names;
    apr_status_t rv = APR_ENOENT;
    STACK_OF(GENERAL_NAME) *xalt_names;
    unsigned char *buf;
    int i;
    
    xalt_names = (GENERAL_NAMES*)X509_get_ext_d2i(cert->x509, NID_subject_alt_name, NULL, NULL);
    if (xalt_names) {
        GENERAL_NAME *cval;
        
        names = apr_array_make(p, sk_GENERAL_NAME_num(xalt_names), sizeof(char *));
        for (i = 0; i < sk_GENERAL_NAME_num(xalt_names); ++i) {
            cval = sk_GENERAL_NAME_value(xalt_names, i);
            switch (cval->type) {
                case GEN_DNS:
                case GEN_URI:
                case GEN_IPADD:
                    ASN1_STRING_to_UTF8(&buf, cval->d.ia5);
                    APR_ARRAY_PUSH(names, const char *) = apr_pstrdup(p, (char*)buf);
                    OPENSSL_free(buf);
                    break;
                default:
                    break;
            }
        }
        rv = APR_SUCCESS;
    }
    *pnames = (APR_SUCCESS == rv)? names : NULL;
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

static apr_status_t cert_to_buffer(buffer *buffer, md_cert_t *cert, apr_pool_t *p)
{
    BIO *bio = BIO_new(BIO_s_mem());
    
    if (!bio) {
        return APR_ENOMEM;
    }

    ERR_clear_error();
    PEM_write_bio_X509(bio, cert->x509);
    if (ERR_get_error() > 0) {
        BIO_free(bio);
        return APR_EINVAL;
    }

    buffer->len = BIO_pending(bio);
    if (buffer->len > 0) {
        buffer->data = apr_palloc(p, buffer->len+1);
        buffer->len = BIO_read(bio, buffer->data, (int)buffer->len);
        buffer->data[buffer->len] = '\0';
    }
    BIO_free(bio);
    return APR_SUCCESS;
}

apr_status_t md_cert_fsave(md_cert_t *cert, apr_pool_t *p, 
                           const char *fname, apr_fileperms_t perms)
{
    buffer buffer;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = cert_to_buffer(&buffer, cert, p))) {
        return md_util_freplace(fname, perms, p, fwrite_buffer, &buffer); 
    }
    return rv;
}

apr_status_t md_cert_to_base64url(const char **ps64, md_cert_t *cert, apr_pool_t *p)
{
    buffer buffer;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = cert_to_buffer(&buffer, cert, p))) {
        *ps64 = md_util_base64url_encode(buffer.data, buffer.len, p);
        return APR_SUCCESS;
    }
    *ps64 = NULL;
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
    apr_array_header_t *certs = NULL;
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
        fclose(f);
        
        if (0 < (err =  ERR_get_error())
            && !(ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
            /* not the expected one when no more PEM encodings are found */
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "reading chain %s: %d", fname, err);
            rv = APR_EINVAL;
            goto out;
        }
        
        if (certs->nelts == 0) {
            /* Did not find any. This is acceptable unless the file has a certain size
             * when we no longer accept it as empty chain file. Something seems to be
             * wrong then. */
            apr_finfo_t info;
            if (APR_SUCCESS == apr_stat(&info, fname, APR_FINFO_SIZE, p) && info.size >= 1024) {
                /* "Too big for a moon." */
                rv = APR_EINVAL;
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                              "no certificates in non-empty chain %s", fname);
                goto out;
            }
        }        
    }
out:
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, p, "read chain file %s, found %d certs", 
                  fname, certs? certs->nelts : 0);
    *pcerts = (APR_SUCCESS == rv)? certs : NULL;
    return rv;
}

apr_status_t md_chain_fsave(apr_array_header_t *certs, apr_pool_t *p, 
                            const char *fname, apr_fileperms_t perms)
{
    FILE *f;
    apr_status_t rv;
    const md_cert_t *cert;
    unsigned long err = 0;
    int i;
    
    rv = md_util_fopen(&f, fname, "w");
    if (rv == APR_SUCCESS) {
        apr_file_perms_set(fname, perms);
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

