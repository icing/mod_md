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

#include <assert.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>

#include "md_json.h"
#include "md.h"
#include "md_log.h"
#include "md_store.h"
#include "md_util.h"


int md_contains(const md_t *md, const char *domain)
{
   return md_array_str_index(md->domains, domain, 0, 0) >= 0;
}

const char *md_common_name(const md_t *md1, const md_t *md2)
{
    int i;
    
    if (md1 == NULL || md1->domains == NULL
        || md2 == NULL || md2->domains == NULL) {
        return NULL;
    }
    
    for (i = 0; i < md1->domains->nelts; ++i) {
        const char *name1 = APR_ARRAY_IDX(md1->domains, i, const char*);
        if (md_contains(md2, name1)) {
            return name1;
        }
    }
    return NULL;
}

int md_domains_overlap(const md_t *md1, const md_t *md2)
{
    return md_common_name(md1, md2) != NULL;
}

md_t *md_create_empty(apr_pool_t *p)
{
    md_t *md = apr_pcalloc(p, sizeof(*md));
    if (md) {
        md->domains = apr_array_make(p, 5, sizeof(const char *));
        md->contacts = apr_array_make(p, 5, sizeof(const char *));
        md->defn_name = "unknown";
        md->defn_line_number = 0;
    }
    return md;
}

int md_equal_domains(const md_t *md1, const md_t *md2)
{
    int i;
    if (md1->domains->nelts == md2->domains->nelts) {
        for (i = 0; i < md1->domains->nelts; ++i) {
            const char *name1 = APR_ARRAY_IDX(md1->domains, i, const char*);
            if (!md_contains(md2, name1)) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

int md_contains_domains(const md_t *md1, const md_t *md2)
{
    int i;
    if (md1->domains->nelts >= md2->domains->nelts) {
        for (i = 0; i < md2->domains->nelts; ++i) {
            const char *name2 = APR_ARRAY_IDX(md2->domains, i, const char*);
            if (!md_contains(md1, name2)) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

md_t *md_get_by_name(struct apr_array_header_t *mds, const char *name)
{
    int i;
    for (i = 0; i < mds->nelts; ++i) {
        md_t *md = APR_ARRAY_IDX(mds, i, md_t *);
        if (!strcmp(name, md->name)) {
            return md;
        }
    }
    return NULL;
}

md_t *md_get_by_dns_overlap(struct apr_array_header_t *mds, const md_t *md)
{
    int i;
    for (i = 0; i < mds->nelts; ++i) {
        md_t *o = APR_ARRAY_IDX(mds, i, md_t *);
        if (strcmp(o->name, md->name) && md_common_name(o, md)) {
            return o;
        }
    }
    return NULL;
}

const char *md_create(md_t **pmd, apr_pool_t *p, apr_array_header_t *domains)
{
    md_t *md;
    
    if (domains->nelts <= 0) {
        return "needs at least one domain name";
    }
    
    md = md_create_empty(p);
    if (!md) {
        return "not enough memory";
    }

    md->domains = md_array_str_compact(p, domains, 0);
    md->name = APR_ARRAY_IDX(md->domains, 0, const char *);
 
    *pmd = md;
    return NULL;   
}

/**************************************************************************************************/
/* lifetime */

md_t *md_copy(apr_pool_t *p, const md_t *src)
{
    md_t *md;
    
    md = apr_pcalloc(p, sizeof(*md));
    if (md) {
        memcpy(md, src, sizeof(*md));
        md->domains = apr_array_copy(p, src->domains);
        md->contacts = apr_array_copy(p, src->contacts);
    }    
    return md;   
}

md_t *md_clone(apr_pool_t *p, const md_t *src)
{
    md_t *md;
    
    md = apr_pcalloc(p, sizeof(*md));
    if (md) {
        md->state = src->state;
        md->name = apr_pstrdup(p, src->name);
        md->domains = md_array_str_compact(p, src->domains, 0);
        md->contacts = md_array_str_clone(p, src->contacts);
        if (src->ca_url) md->ca_url = apr_pstrdup(p, src->ca_url);
        if (src->ca_proto) md->ca_proto = apr_pstrdup(p, src->ca_proto);
        if (src->ca_account) md->ca_account = apr_pstrdup(p, src->ca_account);
        if (src->ca_agreement) md->ca_agreement = apr_pstrdup(p, src->ca_agreement);
        if (src->defn_name) md->defn_name = apr_pstrdup(p, src->defn_name);
        md->defn_line_number = src->defn_line_number;
    }    
    return md;   
}

/**************************************************************************************************/
/* format conversion */

md_json_t *md_to_json(const md_t *md, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        apr_array_header_t *domains = md_array_str_compact(p, md->domains, 0);
        md_json_sets(md->name, json, MD_KEY_NAME, NULL);
        md_json_setsa(domains, json, MD_KEY_DOMAINS, NULL);
        md_json_setsa(md->contacts, json, MD_KEY_CONTACTS, NULL);
        md_json_sets(md->ca_account, json, MD_KEY_CA, MD_KEY_ACCOUNT, NULL);
        md_json_sets(md->ca_proto, json, MD_KEY_CA, MD_KEY_PROTO, NULL);
        md_json_sets(md->ca_url, json, MD_KEY_CA, MD_KEY_URL, NULL);
        md_json_sets(md->ca_agreement, json, MD_KEY_CA, MD_KEY_AGREEMENT, NULL);
        md_json_setl(md->state, json, MD_KEY_STATE, NULL);
        return json;
    }
    return NULL;
}

md_t *md_from_json(md_json_t *json, apr_pool_t *p)
{
    md_t *md = md_create_empty(p);
    if (md) {
        md->name = md_json_dups(p, json, MD_KEY_NAME, NULL);            
        md_json_dupsa(md->domains, p, json, MD_KEY_DOMAINS, NULL);
        md_json_dupsa(md->contacts, p, json, MD_KEY_CONTACTS, NULL);
        md->ca_account = md_json_dups(p, json, MD_KEY_CA, MD_KEY_ACCOUNT, NULL);
        md->ca_proto = md_json_dups(p, json, MD_KEY_CA, MD_KEY_PROTO, NULL);
        md->ca_url = md_json_dups(p, json, MD_KEY_CA, MD_KEY_URL, NULL);
        md->ca_agreement = md_json_dups(p, json, MD_KEY_CA, MD_KEY_AGREEMENT, NULL);
        md->state = (int)md_json_getl(json, MD_KEY_STATE, NULL);
        md->domains = md_array_str_compact(p, md->domains, 0);
        return md;
    }
    return NULL;
}

/**************************************************************************************************/
/* storage */

apr_status_t md_load(md_store_t *store, const char *name, md_t **pmd, apr_pool_t *p)
{
    md_json_t *json;
    apr_status_t rv;
    
    rv = md_store_load_json(store, MD_SG_DOMAINS, name, MD_FN_MD, &json, p);
    if (APR_SUCCESS == rv) {
        *pmd = md_from_json(json, p);
        return APR_SUCCESS;
    }
    return rv;
}

static apr_status_t p_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_t *store = baton;
    md_json_t *json;
    md_t *md;
    int create;
    
    md = va_arg(ap, md_t *);
    create = va_arg(ap, int);

    json = md_to_json(md, ptemp);
    assert(json);
    assert(md->name);
    return md_store_save_json(store, MD_SG_DOMAINS, md->name, MD_FN_MD, json, create);
}

apr_status_t md_save(md_store_t *store, md_t *md, int create)
{
    return md_util_pool_vdo(p_save, store, store->p, md, create, NULL);
}

static apr_status_t p_remove(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_t *store = baton;
    const char *name;
    int force;
    
    name = va_arg(ap, const char *);
    force = va_arg(ap, int);

    assert(name);
    return md_store_remove(store, MD_SG_DOMAINS, name, MD_FN_MD, ptemp, force);
}

apr_status_t md_remove(struct md_store_t *store, const char *name, int force)
{
    return md_util_pool_vdo(p_remove, store, store->p, name, force, NULL);
}

typedef struct {
    apr_pool_t *p;
    apr_array_header_t *mds;
} md_load_ctx;

static int add_md(void *baton, const char *name, const char *aspect, 
                  md_store_vtype_t vtype, void *value)
{
    md_load_ctx *ctx = baton;
    
    if (MD_SV_JSON == vtype && !strcmp(MD_FN_MD, aspect)) {
        const md_t *md = md_from_json(value, ctx->p);
        
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, "adding md %s", md->name);
        APR_ARRAY_PUSH(ctx->mds, md_t *) = md_clone(ctx->p, md);
    }
    return 1;
}

static int md_name_cmp(const void *v1, const void *v2)
{
    return strcmp((*(const md_t**)v1)->name, (*(const md_t**)v2)->name);
}


apr_status_t md_load_all(apr_array_header_t **pmds, md_store_t *store, apr_pool_t *p)
{
    apr_status_t rv;
    md_load_ctx ctx;
    
    ctx.p = p;
    ctx.mds = apr_array_make(p, 5, sizeof(md_t *));
    rv = store->iterate(add_md, &ctx, store, MD_SG_DOMAINS, "*", MD_FN_MD, MD_SV_JSON);
    if (APR_SUCCESS == rv) {
        qsort(ctx.mds->elts, ctx.mds->nelts, sizeof(md_t *), md_name_cmp);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, p, "found %d mds", ctx.mds->nelts);
    }
    *pmds = (APR_SUCCESS == rv)? ctx.mds : NULL;
    return rv;
}

apr_status_t md_load_pkey(struct md_store_t *store, const char *name, 
                          struct md_pkey_t **ppkey, apr_pool_t *p)
{
    return md_store_load(store, MD_SG_DOMAINS, name, MD_FN_PKEY, MD_SV_PKEY, (void**)ppkey, p);
}

apr_status_t md_load_cert(struct md_store_t *store, const char *name, 
                          struct md_cert_t **pcert, apr_pool_t *p)
{
    return md_store_load(store, MD_SG_DOMAINS, name, MD_FN_CERT, MD_SV_CERT, (void**)pcert, p);
}

apr_status_t md_load_chain(struct md_store_t *store, const char *name, 
                           struct apr_array_header_t **pchain, apr_pool_t *p)
{
    return md_store_load(store, MD_SG_DOMAINS, name, MD_FN_CHAIN, MD_SV_CHAIN, (void**)pchain, p);
}
