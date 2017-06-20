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
#include <apr_buckets.h>
#include <apr_hash.h>
#include <apr_uri.h>

#include "../md.h"
#include "../md_crypt.h"
#include "../md_json.h"
#include "../md_jws.h"
#include "../md_http.h"
#include "../md_log.h"
#include "../md_reg.h"
#include "../md_store.h"
#include "../md_util.h"

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"
#include "md_acme_drive.h"

typedef struct {
    md_proto_driver_t *driver;
    md_acme_t *acme;
    md_acme_acct_t *acct;
    md_t *md;
    
    md_acme_authz_set_t *authz_set;
    apr_interval_time_t authz_timeout;
    
} md_acme_driver_t;

/**************************************************************************************************/
/* account setup */

static apr_status_t ad_acct_validate(md_proto_driver_t *d, md_acme_acct_t **pacct)
{
    md_acme_driver_t *ad = d->baton;
    md_acme_acct_t *acct = *pacct;
    apr_status_t rv;
    
    if (APR_SUCCESS != (rv = md_acme_acct_validate(ad->acme, *pacct))) {
        if (APR_ENOENT == rv || APR_EACCES == rv) {
            *pacct = NULL;
            rv = md_acme_acct_disable(acct);
        }
    }
    return rv;
}

static apr_status_t ad_set_acct(md_proto_driver_t *d) 
{
    md_acme_driver_t *ad = d->baton;
    md_t *md = ad->md;
    md_acme_acct_t *acct = NULL;
    apr_status_t rv = APR_SUCCESS;

    ad->acct = NULL;
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: finding account",
                  d->proto->protocol);
    
    /* Get an account for the ACME server for this MD */
    if (ad->md->ca_account) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: checking previous account %s",
                      d->proto->protocol, md->ca_account);
        if (APR_SUCCESS == (rv = md_acme_acct_load(&acct, d->store, md->ca_account, d->p))) {
            rv = ad_acct_validate(d, &acct);
        }
        else if (APR_ENOENT == rv) {
            rv = APR_SUCCESS;
        }
    }
    
    /* If MD has no account, find a local account for server, store at MD */ 
    if (APR_SUCCESS == rv && NULL == acct) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: looking at existing accounts",
                      d->proto->protocol);
        while (NULL == acct 
               && APR_SUCCESS == (rv = md_acme_acct_find(&acct, d->store, ad->acme, d->p))) {
            rv = ad_acct_validate(d, &acct);
        }
        if (!acct && APR_ENOENT == rv) {
            rv = APR_SUCCESS;
        }
    }
    
    if (APR_SUCCESS == rv && NULL == acct) {
        /* 2.2 No local account exists, create a new one */
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: creating new account", 
                      d->proto->protocol);

        if (!ad->md->contacts || apr_is_empty_array(md->contacts)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, d->p, 
                "no contact information for md %s", md->name);            
            return APR_EINVAL;
        }
        
        rv = md_acme_register(&acct, d->store, ad->acme, md->contacts, md->ca_agreement);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, "register new account");
        }
    }
    
    if (APR_SUCCESS == rv) {
        ad->acct = acct;
        /* Persist the account chosen at the md so we use the same on future runs */
        if (!md->ca_account || strcmp(md->ca_account, acct->id)) {
            md->ca_account = acct->id;
            rv = md_save(d->store, md, 0);
        }
    }

    return rv;
}

/**************************************************************************************************/
/* authz/challenge setup */

/**
 * Pre-Req: we have an account for the ACME server that has accepted the current license agreement
 * For each domain in MD: 
 * - check if there already is a valid AUTHZ resource
 * - if ot, create an AUTHZ resource with challenge data 
 */
static apr_status_t ad_setup_authz(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;
    md_t *md = ad->md;
    md_acme_authz_t *authz;
    int i, changed;
    
    assert(ad->md);
    assert(ad->acme);
    assert(ad->acct);

    /* For each domain in MD: AUTHZ setup
     * if an AUTHZ resource is known, check if it is still valid
     * if known AUTHZ resource is not valid, remove, goto 4.1.1
     * if no AUTHZ available, create a new one for the domain, store it
     */
    rv = md_acme_authz_set_load(d->store, md->name, &ad->authz_set, d->p);
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: loading authz data", md->name);
    if (APR_ENOENT == rv) {
        ad->authz_set = md_acme_authz_set_create(d->p, ad->acct->id);
        rv = APR_SUCCESS;
    }
    
    for (i = 0; i < md->domains->nelts && APR_SUCCESS == rv; ++i) {
        const char *domain = APR_ARRAY_IDX(md->domains, i, const char *);
        changed = 0;
        authz = md_acme_authz_set_get(ad->authz_set, domain);
        if (authz) {
            /* check valid */
            rv = md_acme_authz_update(authz, ad->acme, ad->acct, d->p);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: updated authz for %s", 
                          md->name, domain);
            if (APR_SUCCESS != rv) {
                md_acme_authz_set_remove(ad->authz_set, domain);
                authz = NULL;
                changed = 1;
            }
        }
        if (!authz) {
            /* create new one */
            rv = md_acme_authz_register(&authz, ad->acme, domain, ad->acct, d->p);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: created authz for %s", 
                          md->name, domain);
            if (APR_SUCCESS == rv) {
                rv = md_acme_authz_set_add(ad->authz_set, authz);
                changed = 1;
            }
        }
        if (APR_SUCCESS == rv && changed) {
            rv = md_acme_authz_set_save(d->store, md->name, ad->authz_set, 0);
        }
    }
    
    return rv;
}

/**
 * Pre-Req: all domains have a AUTHZ resources at the ACME server
 * For each domain in MD: 
 * - if AUTHZ resource is 'valid' -> continue
 * - if AUTHZ resource is 'pending':
 *   - find preferred challenge choice
 *   - calculate challenge data for httpd to find
 *   - POST challenge start to ACME server
 * For each domain in MD where AUTHZ is 'pending', until overall timeout: 
 *   - wait a certain time, check status again
 * If not all AUTHZ are valid, fail
 */
static apr_status_t ad_start_challenges(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv = APR_SUCCESS;
    md_acme_authz_t *authz;
    int i;
    
    assert(ad->md);
    assert(ad->acme);
    assert(ad->acct);
    assert(ad->authz_set);
    assert(ad->authz_set->authzs->nelts == ad->md->domains->nelts);

    for (i = 0; i < ad->authz_set->authzs->nelts && APR_SUCCESS == rv; ++i) {
        authz = APR_ARRAY_IDX(ad->authz_set->authzs, i, md_acme_authz_t*);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: check AUTHZ for %s", 
                      ad->md->name, authz->domain);
        if (APR_SUCCESS == (rv = md_acme_authz_update(authz, ad->acme, ad->acct, d->p))) {
            switch (authz->state) {
                case MD_ACME_AUTHZ_S_VALID:
                    break;
                case MD_ACME_AUTHZ_S_PENDING:
                    rv = md_acme_authz_respond(authz, ad->acme, ad->acct, d->store, d->p);
                    break;
                default:
                    rv = APR_EINVAL;
                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, 
                                  "%s: unexpected AUTHZ state %d at %s", 
                                  authz->domain, authz->state, authz->location);
                    break;
            }
        }
    }
    
    return rv;
}

static apr_status_t ad_monitor_challenges(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;
    md_acme_authz_t *authz;
    apr_time_t now, giveup = apr_time_now() + ad->authz_timeout;
    apr_interval_time_t nap_duration = apr_time_from_msec(100);
    apr_interval_time_t nap_max = apr_time_from_sec(10);
    int i;
    
    assert(ad->md);
    assert(ad->acme);
    assert(ad->acct);
    assert(ad->authz_set);
    assert(ad->authz_set->authzs->nelts == ad->md->domains->nelts);

    while (1) {
        rv = APR_SUCCESS;
        for (i = 0; i < ad->authz_set->authzs->nelts && APR_SUCCESS == rv; ++i) {
            authz = APR_ARRAY_IDX(ad->authz_set->authzs, i, md_acme_authz_t*);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: check AUTHZ for %s", 
                          ad->md->name, authz->domain);
            if (APR_SUCCESS == (rv = md_acme_authz_update(authz, ad->acme, ad->acct, d->p))) {
                switch (authz->state) {
                    case MD_ACME_AUTHZ_S_VALID:
                        break;
                    case MD_ACME_AUTHZ_S_PENDING:
                        rv = APR_EAGAIN;
                        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, 
                                      "%s: status pending at %s", authz->domain, authz->location);
                        break;
                    default:
                        rv = APR_EINVAL;
                        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, 
                                      "%s: unexpected AUTHZ state %d at %s", 
                                      authz->domain, authz->state, authz->location);
                        break;
                }
            }
        }
        
        now = apr_time_now();
        if (now > giveup) {
            break;
        }
        else if (APR_EAGAIN == rv) {
            apr_interval_time_t left = giveup - now;
            if (nap_duration > left) {
                nap_duration = left;
            }
            if (nap_duration > nap_max) {
                nap_duration = nap_max;
            }
            
            apr_sleep(nap_duration);
            nap_duration *= 2; 
        }
        else {
            break;
        }
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, d->p, 
                  "%s: checked all domain authorizations", ad->md->name);
    return rv;
}

/**************************************************************************************************/
/* cert setup */

/**
 * Pre-Req: all domains have been validated by the ACME server, e.g. all have AUTHZ
 * resources that have status 'valid'
 * - Setup private key, if not already there
 * - Generate a CSR with org, contact, etc
 * - Optionally enable must-staple OCSP extension
 * - Submit CSR, expect 201 with location
 * - POLL location for certificate
 * - store certificate
 * - retrieve cert chain information from cert
 * - GET cert chain
 * - store cert chain
 */
static apr_status_t ad_setup_certificate(md_proto_driver_t *d)
{
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* ACME driving */

static apr_status_t acme_driver_init(md_proto_driver_t *d)
{
    md_acme_driver_t *ad;
    
    ad = apr_pcalloc(d->p, sizeof(*ad));
    
    d->baton = ad;
    ad->driver = d;
    ad->md = md_copy(d->p, d->md);
    ad->authz_timeout = apr_time_from_sec(30);

    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, "%s: driving md %s", 
                  d->proto->protocol, ad->md->name);
    
    /* Find out where we're at with this managed domain */
    return md_acme_create(&ad->acme, d->p, ad->md->ca_url, d->store);
}

static apr_status_t acme_driver_run(md_proto_driver_t *d)
{
    apr_status_t rv = APR_ENOTIMPL;
    md_acme_driver_t *ad = d->baton;
    const char *step;

    assert(ad->md);
    assert(ad->acme);

    step = "ACME setup";
    rv = md_acme_setup(ad->acme);
    
    /* TODO: which challenge types do we support? 
     * Need to know if the server listens to the right ports */
    ad->acme->can_cha_http_01 = 1;

    /* Chose (or create) and ACME account to use */
    if (APR_SUCCESS == rv) {
        step = "choose account";
        rv = ad_set_acct(d);
    }
    
    /* Check that the account agreed to the terms-of-service, otherwise
     * requests for new authorizations are denied. ToS may change during the
     * lifetime of an account */
    if (APR_SUCCESS == rv) {
        step = "check agreement";
        rv = md_acme_acct_check_agreement(ad->acme, ad->acct, ad->md->ca_agreement);
    }
    
    /* Check that we have authz resources with challenge info for each domain */
    if (APR_SUCCESS == rv) {
        step = "check authz";
        rv = ad_setup_authz(d);
    }
    
    /* Start challenges */
    if (APR_SUCCESS == rv) {
        step = "setup challenges";
        rv = ad_start_challenges(d);
    }
    
    /* monitor authz status */
    if (APR_SUCCESS == rv) {
        step = "setup challenges";
        rv = ad_monitor_challenges(d);
    }
    
    /* Setup the certificate */
    if (APR_SUCCESS == rv) {
        step = "create certificate";
        rv = ad_setup_certificate(d);
    }
    
    /* Update MD expiration date */
    if (APR_SUCCESS == rv) {
        step = "completed";
    }
        
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s drive %s, %s", 
                  d->proto->protocol, ad->md->name, step);
    return rv;
}

static md_proto_t ACME_PROTO = {
    MD_PROTO_ACME, acme_driver_init, acme_driver_run
};
 
apr_status_t md_acme_protos_add(apr_hash_t *protos, apr_pool_t *p)
{
    apr_hash_set(protos, MD_PROTO_ACME, sizeof(MD_PROTO_ACME)-1, &ACME_PROTO);
    return APR_SUCCESS;
}
