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

#include <stdio.h>

#include <apr_lib.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "../md_json.h"
#include "../md_log.h"
#include "../md_jws.h"
#include "../md_store.h"
#include "../md_util.h"

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"

static apr_status_t authz_create(md_acme_authz_t **pauthz, apr_pool_t *p, 
                                 const char *domain, const char *location)
{
    md_acme_authz_t *authz;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p, "new authz for %s at %s", domain, location);
    
    authz = apr_pcalloc(p, sizeof(*authz));
    authz->domain = apr_pstrdup(p, domain);
    authz->location = apr_pstrdup(p, location);
    *pauthz = authz;
      
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* Register a new authorization */

typedef struct {
    apr_pool_t *p;
    md_acme_t *acme;
    md_acme_acct_t *acct;
    const char *domain;
    md_acme_authz_t *authz;
} authz_ctx;

static apr_status_t on_init_authz(md_acme_req_t *req, void *baton)
{
    authz_ctx *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->pool);
    md_json_sets("new-authz", jpayload, "resource", NULL);
    md_json_sets("dns", jpayload, "identifier", "type", NULL);
    md_json_sets(ctx->domain, jpayload, "identifier", "value", NULL);
    
    return md_acme_req_body_init(req, jpayload, ctx->acct->key);
} 

static apr_status_t on_success_authz(md_acme_t *acme, const apr_table_t *hdrs, 
                                     md_json_t *body, void *baton)
{
    authz_ctx *ctx = baton;
    const char *location = apr_table_get(hdrs, "location");
    apr_status_t rv = APR_SUCCESS;
    
    if (location) {
        rv = authz_create(&ctx->authz, ctx->p, ctx->domain, location);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, ctx->p, "authz_new at %s", location);
    }
    else {
        rv = APR_EINVAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, ctx->p, "new authz, no location header");
    }
    return rv;
}

apr_status_t md_acme_authz_register(struct md_acme_authz_t **pauthz, md_acme_t *acme, 
                                    const char *domain, md_acme_acct_t *acct, apr_pool_t *p)
{
    apr_status_t rv;
    authz_ctx ctx;
    
    ctx.p = p;
    ctx.acme = acme;
    ctx.acct = acct;
    ctx.domain = domain;
    ctx.authz = NULL;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acct->pool, "create new authz");
    rv = md_acme_req_do(acme, acme->new_authz, on_init_authz, on_success_authz, &ctx);
    *pauthz = (APR_SUCCESS == rv)? ctx.authz : NULL;
    return rv;
} 

/**************************************************************************************************/
/* conversion */

#define MD_KEY_ACCOUNT          "account"
#define MD_KEY_DOMAIN           "domain"
#define MD_KEY_LOCATION         "location"

md_json_t *md_acme_authz_set_to_json(md_acme_authz_set_t *set, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        /* TODO */
    }
    return NULL;
}

md_acme_authz_set_t *md_acme_authz_set_from_json(md_json_t *json, apr_pool_t *p)
{
    md_acme_authz_set_t *set = apr_pcalloc(p, sizeof(*set));
    if (set) {
        /* TODO */
    }
    return NULL;
}

/**************************************************************************************************/
/* persistence */

#define MD_FN_AUTHZ     "authz.json"

apr_status_t md_acme_authz_set_load(struct md_store_t *store, const char *name, 
                                    md_acme_authz_set_t **pauthz_set, apr_pool_t *p)
{
    apr_status_t rv;
    md_json_t *json;
    md_acme_authz_set_t *authz_set;
    
    rv = md_store_load_json(store, MD_SG_DOMAINS, name, MD_FN_AUTHZ, &json, p);
    if (APR_SUCCESS == rv) {
        authz_set = md_acme_authz_set_from_json(json, p);
    }
    *pauthz_set = (APR_SUCCESS == rv)? authz_set : NULL;
    return rv;  
}

