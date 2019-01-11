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

#include <apr_lib.h>
#include <apr_buckets.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "md_jws.h"
#include "md_store.h"
#include "md_util.h"

#include "md_acme.h"
#include "md_acme_authz.h"
#include "md_acme_order.h"


md_acme_order_t *md_acme_order_create(apr_pool_t *p)
{
    md_acme_order_t *authz_set;
    
    authz_set = apr_pcalloc(p, sizeof(*authz_set));
    authz_set->authzs = apr_array_make(p, 5, sizeof(md_acme_authz_t *));
    
    return authz_set;
}

md_acme_authz_t *md_acme_order_get(md_acme_order_t *set, const char *domain)
{
    md_acme_authz_t *authz;
    int i;
    
    assert(domain);
    for (i = 0; i < set->authzs->nelts; ++i) {
        authz = APR_ARRAY_IDX(set->authzs, i, md_acme_authz_t *);
        if (!apr_strnatcasecmp(domain, authz->domain)) {
            return authz;
        }
    }
    return NULL;
}

apr_status_t md_acme_order_add(md_acme_order_t *set, md_acme_authz_t *authz)
{
    md_acme_authz_t *existing;
    
    assert(authz->domain);
    if (NULL != (existing = md_acme_order_get(set, authz->domain))) {
        return APR_EINVAL;
    }
    APR_ARRAY_PUSH(set->authzs, md_acme_authz_t*) = authz;
    return APR_SUCCESS;
}

apr_status_t md_acme_order_remove(md_acme_order_t *set, const char *domain)
{
    md_acme_authz_t *authz;
    int i;
    
    assert(domain);
    for (i = 0; i < set->authzs->nelts; ++i) {
        authz = APR_ARRAY_IDX(set->authzs, i, md_acme_authz_t *);
        if (!apr_strnatcasecmp(domain, authz->domain)) {
            int n = i + 1;
            if (n < set->authzs->nelts) {
                void **elems = (void **)set->authzs->elts;
                memmove(elems + i, elems + n, (size_t)(set->authzs->nelts - n) * sizeof(*elems));
            }
            --set->authzs->nelts;
            return APR_SUCCESS;
        }
    }
    return APR_ENOENT;
}



/**************************************************************************************************/
/* authz_set conversion */

#define MD_KEY_ACCOUNT          "account"
#define MD_KEY_AUTHZS           "authorizations"

static apr_status_t authz_to_json(void *value, md_json_t *json, apr_pool_t *p, void *baton)
{
    (void)baton;
    return md_json_setj(md_acme_authz_to_json(value, p), json, NULL);
}

static apr_status_t authz_from_json(void **pvalue, md_json_t *json, apr_pool_t *p, void *baton)
{
    (void)baton;
    *pvalue = md_acme_authz_from_json(json, p);
    return (*pvalue)? APR_SUCCESS : APR_EINVAL;
}

md_json_t *md_acme_order_to_json(md_acme_order_t *set, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        md_json_seta(set->authzs, authz_to_json, NULL, json, MD_KEY_AUTHZS, NULL);
        return json;
    }
    return NULL;
}

md_acme_order_t *md_acme_order_from_json(md_json_t *json, apr_pool_t *p)
{
    md_acme_order_t *set = md_acme_order_create(p);
    if (set) {
        md_json_geta(set->authzs, authz_from_json, NULL, json, MD_KEY_AUTHZS, NULL);
        return set;
    }
    return NULL;
}

/**************************************************************************************************/
/* persistence */

apr_status_t md_acme_order_load(struct md_store_t *store, md_store_group_t group, 
                                    const char *md_name, md_acme_order_t **pauthz_set, 
                                    apr_pool_t *p)
{
    apr_status_t rv;
    md_json_t *json;
    md_acme_order_t *authz_set;
    
    rv = md_store_load_json(store, group, md_name, MD_FN_AUTHZ, &json, p);
    if (APR_SUCCESS == rv) {
        authz_set = md_acme_order_from_json(json, p);
    }
    *pauthz_set = (APR_SUCCESS == rv)? authz_set : NULL;
    return rv;  
}

static apr_status_t p_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_t *store = baton;
    md_json_t *json;
    md_store_group_t group;
    md_acme_order_t *set;
    const char *md_name;
    int create;
 
    (void)p;   
    group = (md_store_group_t)va_arg(ap, int);
    md_name = va_arg(ap, const char *);
    set = va_arg(ap, md_acme_order_t *);
    create = va_arg(ap, int);

    json = md_acme_order_to_json(set, ptemp);
    assert(json);
    return md_store_save_json(store, ptemp, group, md_name, MD_FN_AUTHZ, json, create);
}

apr_status_t md_acme_order_save(struct md_store_t *store, apr_pool_t *p,
                                    md_store_group_t group, const char *md_name, 
                                    md_acme_order_t *authz_set, int create)
{
    return md_util_pool_vdo(p_save, store, p, group, md_name, authz_set, create, NULL);
}

static apr_status_t p_purge(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_t *store = baton;
    md_acme_order_t *authz_set;
    const md_acme_authz_t *authz;
    md_store_group_t group;
    const char *md_name;
    int i;

    group = (md_store_group_t)va_arg(ap, int);
    md_name = va_arg(ap, const char *);

    if (APR_SUCCESS == md_acme_order_load(store, group, md_name, &authz_set, p)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "authz_set loaded for %s", md_name);
        for (i = 0; i < authz_set->authzs->nelts; ++i) {
            authz = APR_ARRAY_IDX(authz_set->authzs, i, const md_acme_authz_t*);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "authz check %s", authz->domain);
            if (authz->dir) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "authz purge %s", authz->dir);
                md_store_purge(store, p, MD_SG_CHALLENGES, authz->dir);
            }
        }
    }
    return md_store_remove(store, group, md_name, MD_FN_AUTHZ, ptemp, 1);
}

apr_status_t md_acme_order_purge(md_store_t *store, md_store_group_t group,
                                     apr_pool_t *p, const char *md_name)
{
    return md_util_pool_vdo(p_purge, store, p, group, md_name, NULL);
}

