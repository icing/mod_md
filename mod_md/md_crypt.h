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

typedef struct md_pkey md_pkey;

apr_status_t md_crypt_init(apr_pool_t *pool);

apr_status_t md_crypt_pkey_load(md_pkey **ppkey, apr_pool_t *p, const char *fname);
apr_status_t md_crypt_pkey_load_rsa(md_pkey **ppkey, apr_pool_t *p, const char *fname);

void md_crypt_pkey_free(md_pkey *pkey);

apr_status_t md_crypt_pkey_save(md_pkey *pkey, apr_pool_t *p, const char *fname);

apr_status_t md_crypt_pkey_gen_rsa(md_pkey **ppkey, apr_pool_t *p, int bits);

const char *md_crypt_pkey_get_rsa_e64(md_pkey *pkey, apr_pool_t *p);
const char *md_crypt_pkey_get_rsa_n64(md_pkey *pkey, apr_pool_t *p);

apr_status_t md_crypt_sign64(const char **psign64, md_pkey *pkey, apr_pool_t *p, 
                             const char *d, size_t dlen);

#endif /* md_crypt_h */
