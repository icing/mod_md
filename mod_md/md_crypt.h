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

#ifndef mod_md_md_crypt_h
#define mod_md_md_crypt_h

struct apr_array_header_t;

typedef struct md_cert md_cert;
typedef struct md_pkey md_pkey;

apr_status_t md_crypt_init(apr_pool_t *pool);

apr_status_t md_pkey_load(md_pkey **ppkey, apr_pool_t *p, const char *fname);
apr_status_t md_pkey_load_rsa(md_pkey **ppkey, apr_pool_t *p, const char *fname);

void md_pkey_free(md_pkey *pkey);

apr_status_t md_pkey_save(md_pkey *pkey, apr_pool_t *p, const char *fname);

apr_status_t md_pkey_gen_rsa(md_pkey **ppkey, apr_pool_t *p, int bits);

const char *md_pkey_get_rsa_e64(md_pkey *pkey, apr_pool_t *p);
const char *md_pkey_get_rsa_n64(md_pkey *pkey, apr_pool_t *p);

apr_status_t md_crypt_sign64(const char **psign64, md_pkey *pkey, apr_pool_t *p, 
                             const char *d, size_t dlen);

typedef enum {
    MD_CERT_UNKNOWN,
    MD_CERT_VALID,
    MD_CERT_EXPIRED
} md_cert_state_t;

void md_cert_free(md_cert *cert);

apr_status_t md_cert_load(md_cert **pcert, apr_pool_t *p, const char *fname);
apr_status_t md_cert_save(md_cert *cert, apr_pool_t *p, const char *fname);

md_cert_state_t md_cert_state_get(md_cert *cert);

apr_status_t md_cert_load_chain(struct apr_array_header_t **pcerts, 
                                apr_pool_t *p, const char *fname);
apr_status_t md_cert_save_chain(struct apr_array_header_t *certs, 
                                apr_pool_t *p, const char *fname);


#endif /* md_crypt_h */
