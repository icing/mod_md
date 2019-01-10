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
#include "md_acmev2_drive.h"

apr_status_t md_acmev2_drive_renew(md_acme_driver_t *ad, md_proto_driver_t *d)
{
    apr_status_t rv = APR_SUCCESS;
    
    ad->phase = "get certificate";
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: (ACMEv2) need certificate", d->md->name);
    
    /* Chose (or create) and ACME account to use */
    rv = md_acme_drive_set_acct(d);
    
    /* If we know a cert's location, try to get it. Previous download might
     * have failed. If server 404 it, we clear our memory of it. */
    if (APR_SUCCESS == rv && ad->md->cert_url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv2) polling certificate", d->md->name);
        rv = md_acme_drive_cert_poll(d, 1);
        if (APR_STATUS_IS_ENOENT(rv)) {
            /* Server reports to know nothing about it. */
            ad->md->cert_url = NULL;
            rv = md_reg_update(d->reg, d->p, ad->md->name, ad->md, MD_UPD_CERT_URL);
        }
    }
    
    if (APR_SUCCESS == rv && !ad->cert) {
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv2) setup new authorization", d->md->name);
        if (1) {
            rv = APR_ENOTIMPL;
            goto out;
        }
        /*
        if (APR_SUCCESS != (rv = ad_setup_authz(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: setup authz resource", 
                          ad->md->name);
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv2) setup new challenges", d->md->name);
        if (APR_SUCCESS != (rv = ad_start_challenges(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: start challenges", 
                          ad->md->name);
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv2) monitoring challenge status", d->md->name);
        if (APR_SUCCESS != (rv = ad_monitor_challenges(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: monitor challenges", 
                          ad->md->name);
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv2) creating certificate request", d->md->name);
        if (APR_SUCCESS != (rv = md_acme_drive_setup_certificate(d))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: setup certificate", 
                          ad->md->name);
            goto out;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                      "%s: (ACMEv2) received certificate", d->md->name);
        */
    }
out:    
    return rv;
}

