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

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"
#include "md_json.h"
#include "md_log.h"
#include "md_jws.h"
#include "md_util.h"

static apr_status_t authz_create(md_acme_authz **pauthz, apr_pool_t *p, 
                                 const char *domain, md_acme_acct *acct)
{
    md_acme_authz *authz;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p, "generating new authz for %s", domain);
    
    authz = apr_pcalloc(p, sizeof(*authz));
    if (authz) {
        authz->domain = apr_pstrdup(p, domain);
        authz->acct = acct;
        authz->challenges = apr_array_make(p, 5, sizeof(md_acme_challenge *));
    }
    *pauthz = authz;
      
    return (authz && authz->challenges)? APR_SUCCESS : APR_ENOMEM;
}

/**************************************************************************************************/
/* Register a new authorization */

static apr_status_t on_init_authz(md_acme_req *req, void *baton)
{
    md_acme_authz *authz = baton;
    md_acme_acct *acct = authz->acct;
    md_json *jpayload;
    const char *payload;
    size_t payload_len;

    jpayload = md_json_create(req->pool);
    if (jpayload) {
        md_json_sets("new-authz", jpayload, "resource", NULL);
        md_json_sets("dns", jpayload, "identifier", "type", NULL);
        md_json_sets(authz->domain, jpayload, "identifier", "value", NULL);
        
        payload = md_json_writep(jpayload, MD_JSON_FMT_INDENT, req->pool);
        if (payload) {
            payload_len = strlen(payload);
            
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, req->pool, 
                          "authz_new payload(len=%d): %s", payload_len, payload);
            return md_jws_sign(&req->req_json, req->pool, payload, payload_len,
                               req->prot_hdrs, acct->key, NULL);
        }
    }
    return APR_ENOMEM;
} 

static void on_success_authz(md_acme *acme, const char *location, md_json *body, void *baton)
{
    md_acme_authz *authz = baton;
    md_acme_acct *acct = authz->acct;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, acct->pool, 
                  "authz_new success: url=%s\n%s", location, 
                  md_json_writep(body, MD_JSON_FMT_INDENT, acct->pool));
    authz->url = apr_pstrdup(acct->pool, location);
}

apr_status_t md_acme_authz_register(struct md_acme_authz **pauthz, const char *domain, 
                                    md_acme_acct *acct)
{
    md_acme *acme = acct->acme;
    md_acme_authz *authz;
    apr_status_t rv;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->pool, "create new authz");
    rv = authz_create(&authz, acme->pool, domain, acct);
    if (APR_SUCCESS != rv) {
        return rv;
    }
    
    rv = md_acme_req_do(acme, acme->new_authz, on_init_authz, on_success_authz, authz);
    if (APR_SUCCESS == rv) {
        *pauthz = authz;
        return APR_SUCCESS;
    }
    *pauthz = NULL;
    return rv;
} 

