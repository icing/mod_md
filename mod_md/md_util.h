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

apr_status_t md_util_fopen(FILE **pf, const char *fn, const char *mode);

const char *md_util_base64url_encode(const char *data, 
                                     apr_size_t len, apr_pool_t *pool);
apr_size_t md_util_base64url_decode(const char **decoded, const char *encoded, 
                                    apr_pool_t *pool);

const char *md_util_schemify(apr_pool_t *p, const char *s, const char *def_scheme);

#endif /* md_util_h */
