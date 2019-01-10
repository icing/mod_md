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
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_buckets.h>
#include <apr_hash.h>
#include <apr_uri.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_jws.h"
#include "md_http.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"

#include "md_acme_drive.h"
#include "md_acmev1_drive.h"

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
    int i;
    int changed = 0;
    
    assert(ad->md);
    assert(ad->acme);

    ad->phase = "check authz";
    
    /* For each domain in MD: AUTHZ setup
     * if an AUTHZ resource is known, check if it is still valid
     * if known AUTHZ resource is not valid, remove, goto 4.1.1
     * if no AUTHZ available, create a new one for the domain, store it
     */
    rv = md_acme_authz_set_load(d->store, MD_SG_STAGING, md->name, &ad->authz_set, d->p);
    if (!ad->authz_set || APR_STATUS_IS_ENOENT(rv)) {
        ad->authz_set = md_acme_authz_set_create(d->p);
        rv = APR_SUCCESS;
    }
    else if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: loading authz data", md->name);
        md_acme_authz_set_purge(d->store, MD_SG_STAGING, d->p, md->name);
        return APR_EAGAIN;
    }
    
    /* Remove anything we no longer need */
    for (i = 0; i < ad->authz_set->authzs->nelts;) {
        authz = APR_ARRAY_IDX(ad->authz_set->authzs, i, md_acme_authz_t*);
        if (!md_contains(md, authz->domain, 0)) {
            md_acme_authz_set_remove(ad->authz_set, authz->domain);
            changed = 1;
        }
        else {
            ++i;
        }
    }
    
    /* Add anything we do not already have */
    for (i = 0; i < md->domains->nelts && APR_SUCCESS == rv; ++i) {
        const char *domain = APR_ARRAY_IDX(md->domains, i, const char *);
        authz = md_acme_authz_set_get(ad->authz_set, domain);
        if (authz) {
            /* check valid */
            rv = md_acme_authz_update(authz, ad->acme, d->store, d->p);
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
            rv = md_acme_authz_register(&authz, ad->acme, d->store, domain, d->p);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: created authz for %s", 
                          md->name, domain);
            if (APR_SUCCESS == rv) {
                rv = md_acme_authz_set_add(ad->authz_set, authz);
                changed = 1;
            }
        }
    }
    
    /* Save any changes */
    if (APR_SUCCESS == rv && changed) {
        rv = md_acme_authz_set_save(d->store, d->p, MD_SG_STAGING, md->name, ad->authz_set, 0);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, d->p, "%s: saved", md->name);
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
    int i, changed = 0;
    
    assert(ad->md);
    assert(ad->acme);
    assert(ad->authz_set);

    ad->phase = "start challenges";

    for (i = 0; i < ad->authz_set->authzs->nelts && APR_SUCCESS == rv; ++i) {
        authz = APR_ARRAY_IDX(ad->authz_set->authzs, i, md_acme_authz_t*);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: check AUTHZ for %s", 
                      ad->md->name, authz->domain);
        if (APR_SUCCESS != (rv = md_acme_authz_update(authz, ad->acme, d->store, d->p))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, "%s: check authz for %s",
                          ad->md->name, authz->domain);
            break;
        }

        switch (authz->state) {
            case MD_ACME_AUTHZ_S_VALID:
                break;
                
            case MD_ACME_AUTHZ_S_PENDING:
                rv = md_acme_authz_respond(authz, ad->acme, d->store, ad->ca_challenges, 
                                           d->md->pkey_spec, d->p);
                changed = 1;
                break;
                
            default:
                rv = APR_EINVAL;
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, 
                              "%s: unexpected AUTHZ state %d at %s", 
                              authz->domain, authz->state, authz->location);
                break;
        }
    }
    
    if (APR_SUCCESS == rv && changed) {
        rv = md_acme_authz_set_save(d->store, d->p, MD_SG_STAGING, ad->md->name, ad->authz_set, 0);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, d->p, "%s: saved", ad->md->name);
    }
    return rv;
}

static apr_status_t check_challenges(void *baton, int attempt)
{
    md_proto_driver_t *d = baton;
    md_acme_driver_t *ad = d->baton;
    md_acme_authz_t *authz;
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    for (i = 0; i < ad->authz_set->authzs->nelts && APR_SUCCESS == rv; ++i) {
        authz = APR_ARRAY_IDX(ad->authz_set->authzs, i, md_acme_authz_t*);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: check AUTHZ for %s(%d. attempt)", 
                      ad->md->name, authz->domain, attempt);
        if (APR_SUCCESS == (rv = md_acme_authz_update(authz, ad->acme, d->store, d->p))) {
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
    return rv;
}

static apr_status_t ad_monitor_challenges(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;
    
    assert(ad->md);
    assert(ad->acme);
    assert(ad->authz_set);

    ad->phase = "monitor challenges";
    rv = md_util_try(check_challenges, d, 0, ad->authz_monitor_timeout, 0, 0, 1);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, d->p, 
                  "%s: checked all domain authorizations", ad->md->name);
    return rv;
}


apr_status_t md_acmev1_drive_renew(md_acme_driver_t *ad, md_proto_driver_t *d)
{
    apr_status_t rv = APR_SUCCESS;
    
    ad->phase = "get certificate";
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: (ACMEv1) need certificate", d->md->name);
    
    /* Chose (or create) and ACME account to use */
    rv = md_acme_drive_set_acct(d);
    
    /* Check that the account agreed to the terms-of-service, otherwise
     * requests for new authorizations are denied. ToS may change during the
     * lifetime of an account */
    if (APR_SUCCESS == rv) {
        const char *required;
        
        ad->phase = "check agreement";
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv1) check Tems-of-Service agreement", d->md->name);
        
        rv = md_acme_check_agreement(ad->acme, d->p, ad->md->ca_agreement, &required);
        
        if (APR_STATUS_IS_INCOMPLETE(rv) && required) {
            /* The CA wants the user to agree to Terms-of-Services. Until the user
             * has reconfigured and restarted the server, this MD cannot be
             * driven further */
            ad->md->state = MD_S_MISSING;
            md_save(d->store, d->p, MD_SG_STAGING, ad->md, 0);
            
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, 
                          "%s: the CA requires you to accept the terms-of-service "
                          "as specified in <%s>. "
                          "Please read the document that you find at that URL and, "
                          "if you agree to the conditions, configure "
                          "\"MDCertificateAgreement url\" "
                          "with exactly that URL in your Apache. "
                          "Then (graceful) restart the server to activate.", 
                          ad->md->name, required);
            goto out;
        }
    }
    
    /* If we know a cert's location, try to get it. Previous download might
     * have failed. If server 404 it, we clear our memory of it. */
    if (APR_SUCCESS == rv && ad->md->cert_url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv1) polling certificate", d->md->name);
        rv = md_acme_drive_cert_poll(d, 1);
        if (APR_STATUS_IS_ENOENT(rv)) {
            /* Server reports to know nothing about it. */
            ad->md->cert_url = NULL;
            rv = md_reg_update(d->reg, d->p, ad->md->name, ad->md, MD_UPD_CERT_URL);
        }
    }
    
    if (APR_SUCCESS == rv && !ad->cert) {
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv1) setup new authorization", d->md->name);
        if (APR_SUCCESS != (rv = ad_setup_authz(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: setup authz resource", 
                          ad->md->name);
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv1) setup new challenges", d->md->name);
        if (APR_SUCCESS != (rv = ad_start_challenges(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: start challenges", 
                          ad->md->name);
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv1) monitoring challenge status", d->md->name);
        if (APR_SUCCESS != (rv = ad_monitor_challenges(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: monitor challenges", 
                          ad->md->name);
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv1) creating certificate request", d->md->name);
        if (APR_SUCCESS != (rv = md_acme_drive_setup_certificate(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: setup certificate", 
                          ad->md->name);
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv1) received certificate", d->md->name);
    }
out:    
    return rv;
}

