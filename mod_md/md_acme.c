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

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include "md_acme.h"
#include "md_json.h"
#include "md_http.h"

static md_jsel *sel_nauthz;
static md_jsel *sel_ncert;
static md_jsel *sel_nreg;
static md_jsel *sel_rcert;

static apr_status_t init_pool_cleanup(void *data)
{
    (void)data;
    
    sel_nauthz = NULL;
    sel_ncert = NULL;
    sel_nreg = NULL;
    sel_rcert = NULL;
    
    return APR_SUCCESS;
}

apr_status_t md_acme_init(apr_pool_t *p)
{
    md_jsel_create(&sel_nauthz, p, "new-authz");
    md_jsel_create(&sel_ncert, p, "new-cert");
    md_jsel_create(&sel_nreg, p, "new-reg");
    md_jsel_create(&sel_rcert, p, "revoke-cert");
    
    apr_pool_cleanup_register(p, NULL, init_pool_cleanup, apr_pool_cleanup_null);
    return (sel_nauthz && sel_ncert && sel_nreg && sel_rcert)? APR_SUCCESS : APR_ENOMEM;
}

apr_status_t md_acme_create(md_acme **pacme, apr_pool_t *p, const char *url)
{
    md_acme *acme;
    
    acme = apr_pcalloc(p, sizeof(*acme));
    if (!acme) {
        return APR_ENOMEM;
    }
    
    acme->url = url;
    acme->state = MD_ACME_S_INIT;
    acme->pool = p;
    *pacme = acme;
    
    return md_http_create(&acme->http, p);
}

apr_status_t md_acme_setup(md_acme *acme)
{
    apr_status_t status;
    md_json *json;
    
    status = md_json_http_get(&json, acme->pool, acme->http, acme->url);
    if (status == APR_SUCCESS) {
        acme->new_authz = md_json_gets(json, sel_nauthz);
        acme->new_cert = md_json_gets(json, sel_ncert);
        acme->new_reg = md_json_gets(json, sel_nreg);
        acme->revoke_cert = md_json_gets(json, sel_rcert);
        if (acme->new_authz && acme->new_cert && acme->new_reg && acme->revoke_cert) {
            acme->state = MD_ACME_S_LIVE;
            return APR_SUCCESS;
        }
        acme->state = MD_ACME_S_INIT;
        status = APR_EINVAL;
    }
    return status;
}
