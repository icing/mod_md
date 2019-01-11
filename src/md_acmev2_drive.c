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

#define MD_FN_ORDER             "order.json"

/**************************************************************************************************/
/* store presistence */

static apr_status_t order_load(md_acmev2_order_t **porder, md_store_t *store, apr_pool_t *p, const char *name)
{
    md_json_t *json;
    md_acmev2_order_t *order;
    apr_status_t rv;
    
    *porder = NULL;
    rv = md_store_load_json(store, MD_SG_STAGING, name, MD_FN_ORDER, &json, p);
    if (APR_SUCCESS == rv) {
        order = apr_pcalloc(p, sizeof(*order));
        order->url = md_json_gets(json, MD_KEY_URL, NULL);
        order->json = NULL;
        *porder = order;
    }
    return rv;
} 

static apr_status_t order_save(md_acmev2_order_t *order, md_store_t *store, apr_pool_t *p, const char *name)
{
    md_json_t *json;
    
    assert(order);
    assert(order->url);
    
    json = md_json_create(p);
    md_json_sets(order->url, json, MD_KEY_URL, NULL);
    return md_store_save_json(store, p, MD_SG_STAGING, name, MD_FN_ORDER, json, 0);
} 

static apr_status_t order_delete(md_store_t *store, apr_pool_t *p, const char *name)
{
    return md_store_remove(store, MD_SG_STAGING, name, MD_FN_ORDER, p, 1);
} 

/**************************************************************************************************/
/* ACMEv2 order requests */

typedef struct {
    apr_pool_t *p;
    const md_t *md;
    md_acmev2_order_t *order;
} order_ctx_t;

static apr_status_t identifier_to_json(void *value, md_json_t *json, apr_pool_t *p, void *baton)
{
    md_json_t *jid;
    
    (void)baton;
    jid = md_json_create(p);
    md_json_sets("dns", jid, "type", NULL);
    md_json_sets(value, jid, "value", NULL);
    return md_json_setj(jid, json, NULL);
}

static apr_status_t on_init_order_register(md_acme_req_t *req, void *baton)
{
    order_ctx_t *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    md_json_seta(ctx->md->domains, identifier_to_json, NULL, jpayload, "identifiers", NULL);

    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t on_order_upd(md_acme_t *acme, apr_pool_t *p, const apr_table_t *hdrs, 
                                 md_json_t *body, void *baton)
{
    order_ctx_t *ctx = baton;
    const char *location = apr_table_get(hdrs, "location");
    apr_status_t rv = APR_SUCCESS;
    
    (void)acme;
    (void)p;
    if (!ctx->order) {
        if (location) {
            ctx->order = apr_pcalloc(ctx->p, sizeof(md_acmev2_order_t));
            ctx->order->url = apr_pstrdup(ctx->p, location);
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, ctx->p, "new order at %s", location);
        }
        else {
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, ctx->p, "new order, no location header");
            goto out;
        }
    }
    ctx->order->json = md_json_clone(ctx->p, body);
out:
    return rv;
}

static apr_status_t order_register(md_acmev2_order_t **porder, md_acme_t *acme, apr_pool_t *p, 
                                   const md_t *md)
{
    order_ctx_t ctx;
    apr_status_t rv;
    
    ctx.p = p;
    ctx.md = md;
    ctx.order = NULL;
    
    rv = md_acme_POST(acme, acme->api.v2.new_order, on_init_order_register, on_order_upd, NULL, &ctx);
    *porder = (APR_SUCCESS == rv)? ctx.order : NULL;
    return rv;
}

static apr_status_t order_update(md_acmev2_order_t *order, md_acme_t *acme, apr_pool_t *p)
{
    order_ctx_t ctx;
    
    ctx.p = p;
    ctx.md = NULL;
    ctx.order = order;
    
    return md_acme_GET(acme, order->url, NULL, on_order_upd, NULL, &ctx);
}

typedef struct {
    md_proto_driver_t *d;
    md_acme_driver_t *ad;
    md_acmev2_order_t *order;
    apr_status_t rv;
} auth_ctx_t;

static int start_auth(void *baton, size_t index, md_json_t *json)
{
    auth_ctx_t *ctx = baton;
    const char *url = md_json_gets(json, NULL);
    md_json_t *jauth;
    const char *status;
    int proceed = 1;
    apr_status_t rv;
    
    /* An authorization resource is for a single domain name. Initially, it has
     * status "pending" and a list of challenges. Each challenge initially has
     * status "pending" as well.
     * We need to select the challenge that we can answer (not all may be possible)
     * and which we like best (configuration order) and accept that challenge.
     * 
     * Accepting a challenge will trigger the ACME server to hunt for the answer to
     * the challenge. That might be a particular resource on this server or a DNS record, so
     * we need to set that up before accpeting it.
     * 
     * After we tell the ACME server which challenge we accpeted, it will place the
     * challenge and the auth resource into status "processing". Hunting for the challenge
     * answer might take some time and the ACME server is not obliged to do that right away.
     *
     * If the proper answer is found by the ACME server, the challenge and the auth resource
     * will have status "valid". To detect that we need to poll the resource at regular intervals.
     *
     * If the challenge answer was wrong or the challenge timed out before an answer was received,
     * the challenge and the auth resource will have status "invalid". We need to
     * give up on this auth, and therefore on the order it was for. 
     */
    if (APR_SUCCESS != (rv = md_acme_get_json(&jauth, ctx->ad->acme, url, ctx->d->p))) goto out;
    status = md_json_gets(jauth, MD_KEY_STATUS, NULL);
    if (!strcmp("pending", status)) {
        /* start the challenge that we want to use */
        
        rv = APR_EAGAIN;
    }
    else if (!strcmp("processing", status)) {
        rv = APR_SUCCESS;
    }
    else if (!strcmp("valid", status)) {
        rv = APR_SUCCESS;
    }
    else if (!strcmp("invalid", status)) {
        rv = APR_EINVAL;
        proceed = 0;
    }
    else {
        rv = APR_EGENERAL;
        proceed = 0;
    }
    
out:
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ctx->d->p, 
                      "%s: (ACMEv2) process %d. auth: %s", ctx->d->md->name, (int)index, url);
    ctx->rv = rv;
    return proceed;
}

static apr_status_t order_process(md_acmev2_order_t *order, md_acme_driver_t *ad, md_proto_driver_t *d)
{
    apr_status_t rv = APR_EGENERAL;
    const char *status = md_json_gets(order->json, MD_KEY_STATUS, NULL);
    
    (void)ad;
    (void)d;
    if (!strcmp("pending", status)) {
        auth_ctx_t ctx;

        /* The ACMEv2 server offers a "authorization" resource for each domain name we
         * placed in our order. Ininitally, all these are in state "pending". We need
         * to bring them all to status "valid" for the order to succeed. */
        ctx.d = d;
        ctx.ad = ad;
        ctx.order = order;
        ctx.rv = APR_SUCCESS;
        md_json_itera(start_auth, &ctx, order->json, "authorizations", NULL);
        rv = ctx.rv;
    }
    else if (!strcmp("ready", status)) {
        rv = APR_ENOTIMPL;
    }
    else if (!strcmp("processing", status)) {
        rv = APR_ENOTIMPL;
    }
    else if (!strcmp("valid", status)) {
        rv = APR_ENOTIMPL;
    }
    else if (!strcmp("invalid", status)) {
        rv = APR_ENOTIMPL;
    }
    else if (!strcmp("complete", status)) {
        rv = APR_ENOTIMPL;
    }
    else {
        rv = APR_EGENERAL;
    }
    return rv;
}

/**************************************************************************************************/
/* ACMEv2 renewal */

apr_status_t md_acmev2_drive_renew(md_acme_driver_t *ad, md_proto_driver_t *d)
{
    md_acmev2_driver_t *sad = ad->sub_driver;
    apr_status_t rv = APR_SUCCESS;
    
    if (!sad) {
        sad = apr_pcalloc(d->p, sizeof(*sad));
        ad->sub_driver = sad;
    }
    
    ad->phase = "get certificate";
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: (ACMEv2) need certificate", d->md->name);
    
    /* Chose (or create) and ACME account to use */
    if (APR_SUCCESS != (rv = md_acme_drive_set_acct(d))) goto out;

    /* If we know a cert's location, try to get it. Previous download might
     * have failed. If server 404 it, we clear our memory of it. */
    if (ad->md->cert_url) {
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

        if (!sad->order) {
            /* Have we save an order in STAGING? */
            if (APR_SUCCESS == (rv = order_load(&sad->order, d->store, d->p, d->md->name))) {
            }
            else if (APR_STATUS_IS_ENOENT(rv)) {
                sad->order = NULL;
            }
            else if (APR_SUCCESS != rv) {
                goto out;
            }
        }
        
        if (!sad->order) {
            /* No Order to be found, register a new one */
            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                          "%s: (ACMEv2) setup new order", d->md->name);
            if (APR_SUCCESS != (rv = order_register(&sad->order, ad->acme, d->p, d->md))) goto out;
            if (APR_SUCCESS != (rv = order_save(sad->order, d->store, d->p, d->md->name))) goto out;
        }

        rv = order_update(sad->order, ad->acme, d->p);
        if (APR_STATUS_IS_ENOENT(rv)) {
            sad->order = NULL;
            order_delete(d->store, d->p, d->md->name);
        }
        else if (APR_SUCCESS != rv) {
            goto out;
        }

        if (APR_SUCCESS != (rv = order_process(sad->order, ad, d))) goto out;

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

