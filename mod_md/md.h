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

typedef enum {
    MD_CA_S_UNKNOWN,                /* CA state is unknown */
    MD_CA_S_LIVE,                   /* CA has been talked to successfully */
    MD_CA_S_ERR,                    /* CA had error in communication */
} md_ca_state_t;

typedef struct md_ca_t md_ca_t;

struct md_ca_t {
    const char *url;                /* url of CA certificate service */
    const char *proto;              /* protocol used vs CA (e.g. ACME) */
};

#define md_ca_state_get_cb(ca)      ca->state_get(ca)

typedef enum {
    MD_S_INCOMPLETE,                /* MD is missing data, e.g. certificates */
    MD_S_COMPLETE,                  /* MD has all data, can go live */
    MD_S_EXPIRED,                   /* MD has all data, but (part of) is expired */
} md_state_t;

typedef struct md_t {
    const char         *name;       /* unique name of this MD */
    apr_array_header_t *domains;    /* all DNS names this MD includes */
    const md_ca_t      *ca;         /* CA handing out certificates for this MD */
    md_state_t state;               /* state of this MD */

    const char *defn_name;          /* config file this MD was defined */
    unsigned defn_line_number;      /* line number of definition */
} md_t;

/**
 * Determine if the Managed Domain conotains a specific domain.
 */
int md_contains(const md_t *md, const char *domain);

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
