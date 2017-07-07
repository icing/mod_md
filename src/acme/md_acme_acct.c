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
#include <stdio.h>

#include <apr_lib.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "../md.h"
#include "../md_crypt.h"
#include "../md_json.h"
#include "../md_jws.h"
#include "../md_log.h"
#include "../md_store.h"
#include "../md_util.h"
#include "../md_version.h"

#include "md_acme.h"
#include "md_acme_acct.h"

static apr_status_t acct_make(md_acme_acct_t **pacct, apr_pool_t *p, 
                              const char *ca_url, const char *id, apr_array_header_t *contacts)
{
    md_acme_acct_t *acct;
    
    acct = apr_pcalloc(p, sizeof(*acct));

    acct->id = id? apr_pstrdup(p, id) : NULL;
    acct->ca_url = ca_url;
    
    if (!contacts || apr_is_empty_array(contacts)) {
        acct->contacts = apr_array_make(p, 5, sizeof(const char *));
    }
    else {
        acct->contacts = apr_array_copy(p, contacts);
    }
    
    *pacct = acct;
    return APR_SUCCESS;
}


static void md_acme_acct_free(md_acme_acct_t *acct)
{
}

static const char *mk_acct_id(apr_pool_t *p, md_acme_t *acme, int i)
{
    return apr_psprintf(p, "ACME-%s-%04d", acme->sname, i);
}

static const char *mk_acct_pattern(apr_pool_t *p, md_acme_t *acme)
{
    return apr_psprintf(p, "ACME-%s-*", acme->sname);
}
 
/**************************************************************************************************/
/* json load/save */

static md_json_t *acct_to_json(md_acme_acct_t *acct, apr_pool_t *p)
{
    md_json_t *jacct;

    assert(acct);
    jacct = md_json_create(p);
    md_json_sets(acct->id, jacct, MD_KEY_ID, NULL);
    md_json_setb(acct->disabled, jacct, MD_KEY_DISABLED, NULL);
    md_json_sets(acct->url, jacct, MD_KEY_URL, NULL);
    md_json_sets(acct->ca_url, jacct, MD_KEY_CA_URL, NULL);
    md_json_setj(acct->registration, jacct, MD_KEY_REGISTRATION, NULL);
    if (acct->agreement) {
        md_json_sets(acct->agreement, jacct, MD_KEY_AGREEMENT, NULL);
    }
    
    return jacct;
}

static apr_status_t acct_from_json(md_acme_acct_t **pacct, md_json_t *json, apr_pool_t *p)
{
    apr_status_t rv = APR_EINVAL;
    md_acme_acct_t *acct;
    int disabled;
    const char *ca_url, *url, *id;
    apr_array_header_t *contacts;
    
    id = md_json_gets(json, MD_KEY_ID, NULL);
    disabled = md_json_getb(json, MD_KEY_DISABLED, NULL);
    ca_url = md_json_gets(json, MD_KEY_CA_URL, NULL);
    if (!ca_url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "account has no CA url: %s", id);
        goto out;
    }
    
    url = md_json_gets(json, MD_KEY_URL, NULL);
    if (!url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "account has no url: %s", id);
        goto out;
    }

    contacts = apr_array_make(p, 5, sizeof(const char *));
    md_json_getsa(contacts, json, MD_KEY_REGISTRATION, MD_KEY_CONTACT, NULL);
    rv = acct_make(&acct, p, ca_url, id, contacts);
    if (APR_SUCCESS == rv) {
        acct->disabled = disabled;
        acct->url = url;
        acct->agreement = md_json_gets(json, "terms-of-service", NULL);
    }

out:
    *pacct = (APR_SUCCESS == rv)? acct : NULL;
    return rv;
}

static apr_status_t acct_save(md_acme_t *acme)
{
    apr_pool_t *ptemp;
    md_json_t *jacct;
    apr_status_t rv;
    
    assert(acme->acct->id);
    if (APR_SUCCESS == (rv = apr_pool_create(&ptemp, acme->p))) {
        jacct = acct_to_json(acme->acct, ptemp);
        rv = md_store_save(acme->store, MD_SG_ACCOUNTS, 
                           acme->acct->id, MD_FN_ACCOUNT, MD_SV_JSON, jacct, 0);
        apr_pool_destroy(ptemp);
    }
    
    return rv;
}

static apr_status_t acct_create(md_acme_acct_t *acct, md_acme_t *acme)
{
    apr_pool_t *ptemp;
    const char *id;
    md_json_t *jacct;
    int i;
    apr_status_t rv;
    
    rv = apr_pool_create(&ptemp, acme->p);
    if (APR_SUCCESS != rv) {
        return rv;
    }
    
    jacct = acct_to_json(acct, ptemp);

    rv = APR_EAGAIN;
    for (i = 0; i < 1000 && APR_SUCCESS != rv; ++i) {
        id = mk_acct_id(acme->p, acme, i);
        md_json_sets(id, jacct, MD_KEY_ID, NULL);
        rv = md_store_save(acme->store, MD_SG_ACCOUNTS, id, MD_FN_ACCOUNT, MD_SV_JSON, jacct, 1);
    }
    
    if (APR_SUCCESS == rv) {
        acct->id = id;
    }
    
    apr_pool_destroy(ptemp);
    return rv;
}

static apr_status_t acct_load(md_acme_acct_t **pacct, md_pkey_t **ppkey,
                              md_store_t *store, const char *name, apr_pool_t *p)
{
    md_json_t *json;
    apr_status_t rv;

    rv = md_store_load_json(store, MD_SG_ACCOUNTS, name, MD_FN_ACCOUNT, &json, p);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "error reading account: %s", name);
        goto out;
    }
    
    rv = acct_from_json(pacct, json, p);
    if (APR_SUCCESS == rv) {
        rv = md_store_load(store, MD_SG_ACCOUNTS, name, 
                           MD_FN_ACCT_KEY, MD_SV_PKEY, (void**)ppkey, p);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "loading key: %s", name);
            goto out;
        }
    }
out:
    if (APR_SUCCESS != rv) {
        *pacct = NULL;
        *ppkey = NULL;
    } 
    return rv;
}

/**************************************************************************************************/
/* Lookup */

typedef struct {
    apr_pool_t *p;
    md_acme_t *acme;
    const char *id;
} find_ctx;

static int find_acct(void *baton, const char *name, const char *aspect,
                     md_store_vtype_t vtype, void *value, apr_pool_t *ptemp)
{
    find_ctx *ctx = baton;
    md_json_t *json = value;
    int disabled;
    const char *ca_url, *id;
    
    id = md_json_gets(json, MD_KEY_ID, NULL);
    disabled = md_json_getb(json, MD_KEY_DISABLED, NULL);
    ca_url = md_json_gets(json, MD_KEY_CA_URL, NULL);
    
    if (!disabled && ca_url && !strcmp(ctx->acme->url, ca_url)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, 
                      "found account %s for %s: %s, disabled=%d, ca-url=%s", 
                      name, ctx->acme->url, id, disabled, ca_url);
        ctx->id = id;
        return 0;
    }
    return 1;
}

static apr_status_t acct_find(md_acme_acct_t **pacct, md_pkey_t **ppkey, 
                              md_store_t *store, md_acme_t *acme, apr_pool_t *p)
{
    apr_status_t rv;
    find_ctx ctx;
    
    ctx.p = p;
    ctx.acme = acme;
    ctx.id = NULL;
    
    rv = md_store_iter(find_acct, &ctx, store, MD_SG_ACCOUNTS, mk_acct_pattern(p, acme),
                       MD_FN_ACCOUNT, MD_SV_JSON);
    if (ctx.id) {
        rv = acct_load(pacct, ppkey, store, ctx.id, p);
    }
    else {
        *pacct = NULL;
        rv = APR_ENOENT;
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                  "acct_find %s", (*pacct)? (*pacct)->id : "NULL"); 
    return rv;
}

/**************************************************************************************************/
/* Register a new account */

static apr_status_t on_init_acct_new(md_acme_req_t *req, void *baton)
{
    md_acme_t *acme = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    md_json_sets("new-reg", jpayload, MD_KEY_RESOURCE, NULL);
    md_json_setsa(acme->acct->contacts, jpayload, MD_KEY_CONTACT, NULL);
    if (acme->acct->agreement) {
        md_json_sets(acme->acct->agreement, jpayload, MD_KEY_AGREEMENT, NULL);
    }
    
    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t acct_upd(md_acme_t *acme, const apr_table_t *hdrs,
                             md_json_t *body, void *baton)
{
    apr_status_t rv = APR_SUCCESS;
    apr_pool_t *p = acme->p;
    md_acme_acct_t *acct = acme->acct;
    
    if (!acct->url) {
        const char *location = apr_table_get(hdrs, "location");
        if (!location) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, APR_EINVAL, p, "new acct without location");
            return APR_EINVAL;
        }
        acct->url = apr_pstrdup(p, location);
    }
    if (!acct->tos_required) {
        acct->tos_required = md_link_find_relation(hdrs, p, "terms-of-service");
        if (acct->tos_required) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                          "server requires agreement to <%s>", acct->tos_required);
        }
    }
    
    apr_array_clear(acct->contacts);
    md_json_getsa(acct->contacts, body, MD_KEY_CONTACT, NULL);
    acct->registration = md_json_clone(p, body);
    
    if (acme->store) {
        if (acct->id) {
            rv = acct_save(acme);
        }
        else {
           rv = acct_create(acct, acme);
            if (APR_SUCCESS == rv) {
                rv = md_store_save(acme->store, MD_SG_ACCOUNTS, acct->id, 
                                   MD_FN_ACCT_KEY, MD_SV_PKEY, acme->acct_key, 0);
            }
        }
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "updated acct %s", acct->url);
    return rv;
}

static apr_status_t acct_register(md_acme_t *acme, 
                                  apr_array_header_t *contacts, const char *agreement)
{
    apr_status_t rv;
    md_pkey_t *pkey;
    const char *err = NULL, *uri;
    int i;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "create new account");
    
    if (agreement) {
        if (APR_SUCCESS != (rv = md_util_abs_uri_check(acme->p, agreement, &err))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, acme->p, 
                          "invalid agreement uri (%s): %s", err, agreement);
            goto out;
        }
    }
    for (i = 0; i < contacts->nelts; ++i) {
        uri = APR_ARRAY_IDX(contacts, i, const char *);
        if (APR_SUCCESS != (rv = md_util_abs_uri_check(acme->p, uri, &err))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, acme->p, 
                          "invalid contact uri (%s): %s", err, uri);
            goto out;
        }
    }
    
    if (APR_SUCCESS == (rv = md_pkey_gen_rsa(&pkey, acme->p, acme->pkey_bits))
        && APR_SUCCESS == (rv = acct_make(&acme->acct,  acme->p, acme->url, NULL, contacts))) {

        acme->acct_key = pkey;
        if (agreement) {
            acme->acct->agreement = agreement;
        }

        rv = md_acme_POST(acme, acme->new_reg, on_init_acct_new, acct_upd, NULL, acme);
        if (APR_SUCCESS == rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, acme->p, 
                          "registered new account %s", acme->acct->url);
        }
    }

out:    
    if (APR_SUCCESS != rv && acme->acct) {
        md_acme_acct_free(acme->acct);
        acme->acct = NULL;
    }
    return rv;
}

/**************************************************************************************************/
/* acct validation */

static apr_status_t on_init_acct_valid(md_acme_req_t *req, void *baton)
{
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    md_json_sets("reg", jpayload, MD_KEY_RESOURCE, NULL);
    
    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t acct_valid(md_acme_t *acme, const apr_table_t *hdrs, 
                               md_json_t *body, void *baton)
{
    md_acme_acct_t *acct = acme->acct;
    apr_status_t rv = APR_SUCCESS;
    const char *tos_required;
    
    apr_array_clear(acct->contacts);
    md_json_getsa(acct->contacts, body, MD_KEY_CONTACT, NULL);
    acct->registration = md_json_clone(acme->p, body);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acme->p, "validate acct %s: %s", 
                  acct->url, md_json_writep(body, MD_JSON_FMT_INDENT, acme->p));
    
    acct->agreement = md_json_gets(acct->registration, MD_KEY_AGREEMENT, NULL);
    
    tos_required = md_link_find_relation(hdrs, acme->p, "terms-of-service");
    if (tos_required) {
        if (!acct->agreement || strcmp(tos_required, acct->agreement)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acme->p, 
                          "needs to agree to terms-of-service '%s', "
                          "has already agreed to '%s'", 
                          tos_required, acct->agreement);
        }
        acct->tos_required = tos_required;
    }
    
    return rv;
}

static apr_status_t md_acme_validate_acct(md_acme_t *acme)
{
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "acct validation");
    if (!acme->acct) {
        return APR_EINVAL;
    }
    return md_acme_POST(acme, acme->acct->url, on_init_acct_valid, acct_valid, NULL, NULL);
}

/**************************************************************************************************/
/* account setup */

static apr_status_t acct_validate(md_acme_t *acme)
{
    apr_status_t rv;
    
    if (APR_SUCCESS != (rv = md_acme_validate_acct(acme))) {
        if (acme->acct && (APR_ENOENT == rv || APR_EACCES == rv)) {
            if (!acme->acct->disabled) {
                acme->acct->disabled = 1;
                if (acme->store) {
                    acct_save(acme);
                }
            }
            acme->acct = NULL;
            acme->acct_key = NULL;
            rv = APR_ENOENT;
        }
    }
    return rv;
}

apr_status_t md_acme_use_acct(md_acme_t *acme, const char *acct_id)
{
    md_acme_acct_t *acct;
    md_pkey_t *pkey;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = acct_load(&acct, &pkey, acme->store, acct_id, acme->p))) {
        acme->acct = acct;
        acme->acct_key = pkey;
        rv = acct_validate(acme);
    }
    return rv;
}

const char *md_acme_get_acct(md_acme_t *acme)
{
    return acme->acct? acme->acct->id : NULL;
}

const char *md_acme_get_agreement(md_acme_t *acme)
{
    return acme->acct? acme->acct->agreement : NULL;
}

apr_status_t md_acme_find_acct(md_acme_t *acme)
{
    md_acme_acct_t *acct;
    md_pkey_t *pkey;
    apr_status_t rv;
    
    while (APR_SUCCESS == acct_find(&acct, &pkey, acme->store, acme, acme->p)) {
        acme->acct = acct;
        acme->acct_key = pkey;
        rv = acct_validate(acme);
        
        if (APR_SUCCESS == rv) {
            return rv;
        }
        else {
            acme->acct = NULL;
            acme->acct_key = NULL;
            if (!APR_STATUS_IS_ENOENT(rv)) {
                /* encountered error with server */
                return rv;
            }
        }
    }
    return APR_ENOENT;
}

apr_status_t md_acme_create_acct(md_acme_t *acme, apr_array_header_t *contacts, 
                                 const char *agreement)
{
    return acct_register(acme, contacts, agreement);
}

/**************************************************************************************************/
/* Delete the account */

apr_status_t md_acme_unstore_acct(md_store_t *store, const char *acct_id) 
{
    apr_status_t rv = APR_SUCCESS;
    apr_pool_t *p = store->p;
    
    rv = md_store_remove(store, MD_SG_ACCOUNTS, acct_id, MD_FN_ACCOUNT, p, 1);
    if (APR_SUCCESS == rv) {
        md_store_remove(store, MD_SG_ACCOUNTS, acct_id, MD_FN_ACCT_KEY, p, 1);
    }
    return rv;
}

static apr_status_t on_init_acct_del(md_acme_req_t *req, void *baton)
{
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    md_json_sets("reg", jpayload, MD_KEY_RESOURCE, NULL);
    md_json_setb(1, jpayload, "delete", NULL);
    
    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t acct_del(md_acme_t *acme, const apr_table_t *hdrs, md_json_t *body, void *baton)
{
    apr_status_t rv = APR_SUCCESS;
    apr_pool_t *p = acme->p;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, p, "deleted account %s", acme->acct->url);
    if (acme->store) {
        rv = md_acme_unstore_acct(acme->store, acme->acct->id);
        acme->acct = NULL;
        acme->acct_key = NULL;
    }
    return rv;
}

apr_status_t md_acme_delete_acct(md_acme_t *acme)
{
    md_acme_acct_t *acct = acme->acct;
    
    if (!acct) {
        return APR_EINVAL;
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "delete account %s from %s", 
                  acct->url, acct->ca_url);
    return md_acme_POST(acme, acct->url, on_init_acct_del, acct_del, NULL, NULL);
}

/**************************************************************************************************/
/* terms-of-service */

static apr_status_t on_init_agree_tos(md_acme_req_t *req, void *baton)
{
    md_acme_t *acme = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    md_json_sets("reg", jpayload, MD_KEY_RESOURCE, NULL);
    md_json_sets(acme->acct->agreement, jpayload, MD_KEY_AGREEMENT, NULL);
    
    return md_acme_req_body_init(req, jpayload);
} 

apr_status_t md_acme_agree(md_acme_t *acme, const char *agreement)
{
    acme->acct->agreement = agreement;
    return md_acme_POST(acme, acme->acct->url, on_init_agree_tos, acct_upd, NULL, acme);
}

static int agreement_required(md_acme_acct_t *acct)
{
    return (!acct->agreement 
            || (acct->tos_required && strcmp(acct->tos_required, acct->agreement)));
}

apr_status_t md_acme_check_agreement(md_acme_t *acme, const char *agreement)
{
    apr_status_t rv = APR_SUCCESS;
    
    /* Check if (correct) Terms-of-Service for account were accepted */
    if (agreement_required(acme->acct)) {
        const char *tos = acme->acct->tos_required;
        if (!tos) {
            if (APR_SUCCESS != (rv = md_acme_validate_acct(acme))) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acme->p, 
                              "validate for account %", acme->acct->id); 
                return rv;
            }
            tos = acme->acct->tos_required; 
            if (!tos) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, acme->p, "unknown terms-of-service "
                              "required after validation of account %", acme->acct->id); 
                return APR_EGENERAL;
            }
        }
        
        if (acme->acct->agreement && !strcmp(tos, acme->acct->agreement)) {
            rv = md_acme_agree(acme, tos);
        }
        else if (agreement && !strcmp(tos, agreement)) {
            rv = md_acme_agree(acme, tos);
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->p, 
                          "need to accept terms-of-service <%s> for account %s", 
                          tos, acme->acct->id);
            rv = APR_EACCES;
        }
    }
    return rv;
}        
