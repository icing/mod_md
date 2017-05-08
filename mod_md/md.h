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

#ifndef mod_md_md_h
#define mod_md_md_h

typedef struct md_ca_t {
    const char *url;
    const char *proto;
} md_ca_t;

typedef struct md_t {
    const char         *name;
    apr_array_header_t *domains;
    const md_ca_t      *ca;

    const char *defn_name;
    unsigned defn_line_number;
} md_t;

/**
 * Determine if the names of the two managed domains overlap.
 */
int md_names_overlap(const md_t *md1, const md_t *md2);
 
/**
 * Get one common domain name of the two managed domains or NULL.
 */
const char *md_common_name(const md_t *md1, const md_t *md2);

/**
 * Create a managed domain, given a list of domain names.
 */
const char *md_create(md_t **pmd, apr_pool_t *p, int argc, char *const argv[]);

md_t *md_clone(apr_pool_t *p, md_t *src);

#endif /* mod_md_md_h */
