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

#ifndef mod_md_md_util_h
#define mod_md_md_util_h

#define MD_FPROT_F_UONLY      (APR_FPROT_UREAD|APR_FPROT_UWRITE)
#define MD_FPROT_D_UONLY      (APR_FPROT_UREAD|APR_FPROT_UWRITE|APR_FPROT_UEXECUTE)

apr_status_t md_util_fopen(FILE **pf, const char *fn, const char *mode);

apr_status_t md_util_fcreatex(apr_file_t **pf, const char *fn, apr_pool_t *p);

const char *md_util_base64url_encode(const char *data, 
                                     apr_size_t len, apr_pool_t *pool);
apr_size_t md_util_base64url_decode(const char **decoded, const char *encoded, 
                                    apr_pool_t *pool);

const char *md_util_schemify(apr_pool_t *p, const char *s, const char *def_scheme);

const char *md_link_find_relation(const apr_table_t *headers, 
                                  apr_pool_t *pool, const char *relation);

#endif /* md_util_h */
