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

#ifndef mod_md_md_acme_authz_h
#define mod_md_md_acme_authz_h

struct apr_array_header_t;
struct md_acme;
struct md_acme_acct;

typedef struct md_acme_challenge md_acme_challenge;

struct md_acme_challenge {
    const char *url;
    const char *type;
    const char *token;
};

typedef struct md_acme_authz md_acme_authz;

struct md_acme_authz {
    const char *domain;
    struct md_acme_acct *acct;
    md_acme_state_t state;
    const char *url;
    struct apr_array_header_t *challenges;
    apr_time_t expires;
};

apr_status_t md_acme_authz_register(struct md_acme_authz **pauthz, const char *domain, 
                                    md_acme_acct *acct);


#endif /* md_acme_authz_h */
