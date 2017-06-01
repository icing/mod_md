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
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_buckets.h>
#include <apr_getopt.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "md.h"
#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"
#include "mod_md.h"
#include "md_version.h"
#include "md_cmd.h"
#include "md_cmd_acme.h"

/**************************************************************************************************/
/* command: acme newreg */

static apr_status_t cmd_acme_newreg(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    const char **cpp;
    md_acme_acct *acct;
    int i;
    
    apr_array_header_t *contacts = apr_array_make(ctx->p, 5, sizeof(const char *));
    for (i = 0; i < ctx->argc; ++i) {
        cpp = (const char **)apr_array_push(contacts);
        *cpp = md_util_schemify(ctx->p, ctx->argv[i], "mailto");
    }
    if (apr_is_empty_array(contacts)) {
        return usage(cmd, "newreg needs at least one contact email as argument");
    }

    rv = md_acme_register(&acct, ctx->acme, contacts, ctx->tos);
    
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "registered: %s\n", acct->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "register new account");
    }
    
    return rv;
}

static md_cmd_t AcmeNewregCmd = {
    "newreg", MD_CTX_ACME, 
    NULL, cmd_acme_newreg, MD_NoOptions, NULL,
    "newreg contact-uri [contact-uri...]",
    "register a new account at ACME server with give contact uri (email)",
};

/**************************************************************************************************/
/* command: acme agree */

static apr_status_t acct_agree_tos(md_acme *acme, const char *acct_url, const char *tos) 
{
    md_http_t *http;
    md_acme_acct *acct;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json_t *json;
    
    acct = md_acme_acct_get(acme, acct_url);
    if (!acct) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "unknown account: %s", acct_url);
        return APR_ENOENT;
    }
    
    if (!tos) {
        tos = acct->tos;
        if (!tos) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, acme->pool, 
                "terms-of-service not specified (--terms), using default %s", TOS_DEFAULT);
            tos = TOS_DEFAULT;
        }
    }
    rv = md_acme_acct_agree_tos(acct, tos);
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "agreed terms-of-service: %s\n", acct->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "agree to terms-of-service %s", tos);
    }
    return rv;
}

static apr_status_t cmd_acme_agree(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    for (i = 0; i < ctx->argc; ++i) {
        rv = acct_agree_tos(ctx->acme, ctx->argv[i], ctx->tos);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

static md_cmd_t AcmeAgreeCmd = {
    "agree", MD_CTX_ACME, 
    NULL, cmd_acme_agree, MD_NoOptions, NULL,
    "agree account",
    "agree to ACME terms of service",
};

/**************************************************************************************************/
/* command: acme delreg */

static apr_status_t acme_delreg(md_acme *acme, const char *acct_url) 
{
    md_http_t *http;
    md_acme_acct *acct;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json_t *json;
    
    acct = md_acme_acct_get(acme, acct_url);
    if (!acct) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "unknown account: %s", acct_url);
        return APR_ENOENT;
    }
    
    rv = md_acme_acct_del(acct);
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "deleted: %s\n", acct->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "delete account");
    }
    return rv;
}

static apr_status_t cmd_acme_delreg(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    for (i = 0; i < ctx->argc; ++i) {
        rv = acme_delreg(ctx->acme, ctx->argv[i]);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

static md_cmd_t AcmeDelregCmd = {
    "delreg", MD_CTX_ACME, 
    NULL, cmd_acme_delreg, MD_NoOptions, NULL,
    "delreg account",
    "delete an existing ACME account",
};

/**************************************************************************************************/
/* command: acme authz */

static apr_status_t acme_newauthz(md_acme_acct *acct, const char *domain) 
{
    md_acme *acme = acct->acme;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json_t *json;
    md_acme_authz *authz;
    
    rv = md_acme_authz_register(&authz, domain, acct); 
    
    if (rv == APR_SUCCESS) {
        fprintf(stdout, "authz: %s %s\n", domain, authz->url);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, acme->pool, "register new authz");
    }
    return rv;
}

static apr_status_t cmd_acme_authz(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    const char *s;
    md_acme_acct *acct;
    apr_status_t rv;
    int i;
    
    if (ctx->argc <= 0) {
        return usage(cmd, NULL);
    }
    s = ctx->argv[0];
    acct = md_acme_acct_get(ctx->acme, s);
    if (!acct) {
        fprintf(stderr, "unknown account: %s\n", s);
        return APR_EGENERAL;
    }
    
    for (i = 1; i < ctx->argc; ++i) {
        rv = acme_newauthz(acct, ctx->argv[i]);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

static md_cmd_t AcmeAuthzCmd = {
    "authz", MD_CTX_ACME, 
    NULL, cmd_acme_authz, MD_NoOptions, NULL,
    "authz account domain",
    "request a new authorization for an account and domain",
};

/**************************************************************************************************/
/* command: acme list */

static int acct_print(void *baton, const void *key, apr_ssize_t klen, const void *value)
{
    apr_pool_t *pool = baton;
    const md_acme_acct *acct = value;
    md_json_t *json;
    
    json = md_json_create(pool);
    md_json_sets(acct->name, json, "name", NULL);
    md_json_sets(acct->url, json, "url", NULL);
    md_json_setsa(acct->contacts, json, "contact", NULL);
    fprintf (stdout, "%s\n", md_json_writep(json, MD_JSON_FMT_INDENT, pool));
    return 1;
}

static apr_status_t cmd_acme_list(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    md_http_t *http;
    md_acme_acct *acct;
    apr_status_t rv;
    long req_id;
    const char *data;
    md_json_t *json;
    
    fprintf(stdout, "ACME server at %s\n", ctx->acme->url);
    fprintf(stdout, "accounts: %d\n", apr_hash_count(ctx->acme->accounts));
    apr_hash_do(acct_print, ctx->p, ctx->acme->accounts);
    
    return rv;
}

static md_cmd_t AcmeListCmd = {
    "list", MD_CTX_ACME, 
    NULL, cmd_acme_list, MD_NoOptions, NULL,
    "list",
    "list all known ACME accounts",
};

/**************************************************************************************************/
/* command: acme */

static const md_cmd_t *AcmeSubCmds[] = {
    &AcmeNewregCmd,
    &AcmeDelregCmd,
    &AcmeAgreeCmd,
    &AcmeAuthzCmd,
    &AcmeListCmd,
    NULL
};

md_cmd_t MD_AcmeCmd = {
    "acme", MD_CTX_ACME,  
    NULL, NULL, MD_NoOptions, AcmeSubCmds,
    "acme cmd [opts] [args]", 
    "play with the ACME server", 
};
