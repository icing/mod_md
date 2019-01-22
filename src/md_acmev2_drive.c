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
#include "md_acme_order.h"

#include "md_acme_drive.h"
#include "md_acmev2_drive.h"



/**************************************************************************************************/
/* order setup */

/**
 * Either we have an order stored in the STAGING area, or we need to create a 
 * new one at the ACME server.
 */
static apr_status_t ad_setup_order(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;
    md_t *md = ad->md;
    
    assert(ad->md);
    assert(ad->acme);

    ad->phase = "setup order";
    
    /* For each domain in MD: AUTHZ setup
     * if an AUTHZ resource is known, check if it is still valid
     * if known AUTHZ resource is not valid, remove, goto 4.1.1
     * if no AUTHZ available, create a new one for the domain, store it
     */
    rv = md_acme_order_load(d->store, MD_SG_STAGING, md->name, &ad->order, d->p);
    if (!ad->order || APR_STATUS_IS_ENOENT(rv)) {
        rv = APR_SUCCESS;
    }
    else if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: loading order", md->name);
        md_acme_order_purge(d->store, d->p, MD_SG_STAGING, md->name);
        rv = APR_EAGAIN;
        goto out;
    }
    
    if (!ad->order) {
        /* No Order to be found, register a new one */
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: (ACMEv2) register order", d->md->name);
        if (APR_SUCCESS != (rv = md_acme_order_register(&ad->order, ad->acme, d->p, d->md))) goto out;
        if (APR_SUCCESS != (rv = md_acme_order_save(d->store, d->p, MD_SG_STAGING, d->md->name, ad->order, 0))) goto out;
    }
    
out:
    return rv;
}

/**************************************************************************************************/
/* ACMEv2 renewal */

apr_status_t md_acmev2_drive_renew(md_acme_driver_t *ad, md_proto_driver_t *d)
{
    apr_status_t rv = APR_SUCCESS;
    
    ad->phase = "get certificate";
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: (ACMEv2) need certificate", d->md->name);
    
    /* Chose (or create) and ACME account to use */
    if (APR_SUCCESS != (rv = md_acme_drive_set_acct(d))) goto out;

    if (APR_SUCCESS == rv && md_array_is_empty(ad->certs)) {
        
        /* ACMEv2 strategy:
         * 1. load an md_acme_order_t from STAGING, if present
         * 2. if no order found, register a new order at ACME server
         * 3. update the order from the server
         * 4. Switch order state:
         *   * PENDING: process authz challenges
         *   * READY: finalize the order
         *   * PROCESSING: wait and re-assses later
         *   * VALID: retrieve certificate
         *   * COMPLETE: all done, return success
         *   * INVALID and otherwise: fail renewal, delete local order
         */

        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv1) setup new authorization", d->md->name);
        if (APR_SUCCESS != (rv = ad_setup_order(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: setup authz resource", 
                          ad->md->name);
            goto out;
        }
        
        rv = md_acme_order_update(ad->order, ad->acme, d->p);
        if (APR_STATUS_IS_ENOENT(rv)) {
            ad->order = NULL;
            md_acme_order_purge(d->store, d->p, MD_SG_STAGING, d->md->name);
        }
        else if (APR_SUCCESS != rv) {
            goto out;
        }

        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: setup order", d->md->name);
        if (APR_SUCCESS != (rv = ad_setup_order(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: setup authz resource", 
                          ad->md->name);
            goto out;
        }

        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: setup new challenges", d->md->name);
        ad->phase = "start challenges";
        if (APR_SUCCESS != (rv = md_acme_order_start_challenges(ad->order, ad->acme,
                                                                ad->ca_challenges,
                                                                d->store, d->md, d->p))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: start challenges", 
                          ad->md->name);
            goto out;
        }
        
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: monitoring challenge status", d->md->name);
        ad->phase = "monitor challenges";
        if (APR_SUCCESS != (rv = md_acme_order_monitor_authzs(ad->order, ad->acme, d->md,
                                                              ad->authz_monitor_timeout, d->p))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: monitor challenges", 
                          ad->md->name);
            goto out;
        }
        
        if (APR_SUCCESS != (rv = md_acme_order_await_ready(ad->order, ad->acme, d->md, 
                                                           ad->authz_monitor_timeout, d->p))) goto out; 
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, 
                      "%s: order status: %d", d->md->name, ad->order->status); 

        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: finalizing order", d->md->name);
        ad->phase = "finalize order";
        if (APR_SUCCESS != (rv = md_acme_drive_setup_certificate(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: finalize order", ad->md->name);
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: finalized order", d->md->name);
        
        if (APR_SUCCESS != (rv = md_acme_order_await_valid(ad->order, ad->acme, d->md, 
                                                           ad->authz_monitor_timeout, d->p))) goto out;
        if (!ad->order->certificate) {
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, d->p, 
                          "%s: order valid, but certifiate url is missing", d->md->name); 
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, 
                      "%s: order status: %d, certificate at %s", d->md->name, 
                      ad->order->status, ad->order->certificate); 
    }
out:    
    return rv;
}

