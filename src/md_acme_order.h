/* Copyright 2019 greenbytes GmbH (https://www.greenbytes.de)
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

#ifndef md_acme_order_h
#define md_acme_order_h

struct md_json_t;

typedef struct md_acme_order_t md_acme_order_t;

struct md_acme_order_t {
    const char *url;
    struct md_json_t *json;
    struct apr_array_header_t *authzs;
};

/**************************************************************************************************/
/* set of authz data for a managed domain */


md_acme_order_t *md_acme_order_create(apr_pool_t *p);
md_acme_authz_t *md_acme_order_get(md_acme_order_t *set, const char *domain);
apr_status_t md_acme_order_add(md_acme_order_t *set, md_acme_authz_t *authz);
apr_status_t md_acme_order_remove(md_acme_order_t *set, const char *domain);

struct md_json_t *md_acme_order_to_json(md_acme_order_t *set, apr_pool_t *p);
md_acme_order_t *md_acme_order_from_json(struct md_json_t *json, apr_pool_t *p);

apr_status_t md_acme_order_load(struct md_store_t *store, md_store_group_t group, 
                                    const char *md_name, md_acme_order_t **pauthz_set, 
                                    apr_pool_t *p);
apr_status_t md_acme_order_save(struct md_store_t *store, apr_pool_t *p, 
                                    md_store_group_t group, const char *md_name, 
                                    md_acme_order_t *authz_set, int create);

apr_status_t md_acme_order_purge(struct md_store_t *store, md_store_group_t group,
                                     apr_pool_t *p, const char *md_name);


#endif /* md_acme_order_h */
