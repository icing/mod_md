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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_hash.h>
#include <apr_time.h>
#include <apr_strings.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_log.h"
#include "md_http.h"
#include "md_store.h"
#include "md_util.h"
#include "md_ocsp.h"

#define MD_OTHER            "other"

#define MD_OCSP_ID_LENGTH   SHA_DIGEST_LENGTH
   
struct md_ocsp_reg_t {
    apr_pool_t *p;
    md_store_t *store;
    apr_hash_t *hash;
};

typedef struct md_ocsp_status_t md_ocsp_status_t; 
struct md_ocsp_status_t {
    char id[MD_OCSP_ID_LENGTH];
    OCSP_CERTID *certid;
    md_data_t resp_der;
};

static apr_status_t init_cert_id(char *buffer, apr_size_t len, md_cert_t *cert)
{
    X509 *x = md_cert_get_X509(cert);
    
    assert(len == SHA_DIGEST_LENGTH);
    if (X509_digest(x, EVP_sha1(), (unsigned char*)buffer, NULL) != 1) {
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

static int ocsp_status_cleanup(void *ctx, const void *key, apr_ssize_t klen, const void *val)
{
    md_ocsp_reg_t *reg = ctx;
    md_ocsp_status_t *ostat = (md_ocsp_status_t *)val;
    
    (void)reg;
    (void)key;
    (void)klen;
    if (ostat->certid) {
        OCSP_CERTID_free(ostat->certid);
        ostat->certid = NULL;
    }
    return 1;
}

static apr_status_t ocsp_reg_cleanup(void *data)
{
    md_ocsp_reg_t *reg = data;
    
    /* free all OpenSSL structures that we hold */
    if (reg->hash) {
       apr_hash_do(ocsp_status_cleanup, reg, reg->hash);
    }
    return APR_SUCCESS;
}

apr_status_t md_ocsp_reg_make(md_ocsp_reg_t **preg, apr_pool_t *p, md_store_t *store)
{
    md_ocsp_reg_t *reg;
    apr_status_t rv = APR_SUCCESS;
    
    reg = apr_palloc(p, sizeof(*reg));
    if (!reg) {
        rv = APR_ENOMEM;
        goto leave;
    }
    reg->p = p;
    reg->store = store;
    reg->hash = apr_hash_make(p);
    apr_pool_cleanup_register(p, reg, ocsp_reg_cleanup, apr_pool_cleanup_null);
leave:
    *preg = (APR_SUCCESS == rv)? reg : NULL;
    return rv;
}

apr_status_t md_ocsp_prime(md_ocsp_reg_t *reg, md_cert_t *cert, md_cert_t *issuer, const md_t *md)
{
    char id[MD_OCSP_ID_LENGTH];
    md_ocsp_status_t *ostat;
    apr_status_t rv;
    
    rv = init_cert_id(id, sizeof(id), cert);
    if (APR_SUCCESS != rv) goto leave;
    
    ostat = apr_hash_get(reg->hash, id, sizeof(id));
    if (ostat) goto leave; /* already seen it, cert is used in >1 server_rec */
    
    ostat = apr_pcalloc(reg->p, sizeof(*ostat));
    memcpy(ostat->id, id, sizeof(ostat->id));
    
    ostat->certid = OCSP_cert_to_id(NULL, md_cert_get_X509(cert), md_cert_get_X509(issuer));
    if (!ostat->certid) {
        rv = APR_EGENERAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, reg->p, 
                      "md[%s]: unable to create OCSP certid for certificate with serial %s", 
                      md? md->name : MD_OTHER, md_cert_get_serial_number(cert, reg->p));
        goto leave;
    }
    
    apr_hash_set(reg->hash, ostat->id, sizeof(ostat->id), ostat);
    rv = APR_SUCCESS;
leave:
    return rv;
}

apr_status_t md_ocsp_get_status(unsigned char **pder, int *pderlen,
                                md_ocsp_reg_t *reg, md_cert_t *cert,
                                apr_pool_t *p, const md_t *md)
{
    char id[MD_OCSP_ID_LENGTH];
    md_ocsp_status_t *ostat;
    apr_status_t rv;
    
    (void)p;
    (void)md;
    rv = init_cert_id(id, sizeof(id), cert);
    if (APR_SUCCESS != rv) goto leave;
    
    ostat = apr_hash_get(reg->hash, id, sizeof(id));
    if (!ostat) {
        rv = APR_ENOENT;
        goto leave;
    }
    
    *pder = NULL;
    *pderlen = 0;
    if (ostat->resp_der.len <= 0) goto leave;

    *pder = malloc(ostat->resp_der.len);
    if (*pder == NULL) {
        rv = APR_ENOMEM;
        goto leave;
    }
    memcpy(*pder, ostat->resp_der.data, ostat->resp_der.len);
    *pderlen = (int)ostat->resp_der.len;
leave:
    return rv;
}
