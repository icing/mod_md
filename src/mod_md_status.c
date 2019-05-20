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
#include <apr_optional.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include "mod_status.h"

#include "md.h"
#include "md_curl.h"
#include "md_crypt.h"
#include "md_http.h"
#include "md_json.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_util.h"
#include "md_version.h"
#include "md_acme.h"
#include "md_acme_authz.h"

#include "mod_md.h"
#include "mod_md_private.h"
#include "mod_md_config.h"
#include "mod_md_drive.h"
#include "mod_md_status.h"

/**************************************************************************************************/
/* Certificate status */

#define APACHE_PREFIX               "/.httpd/"
#define MD_STATUS_RESOURCE          APACHE_PREFIX"certificate-status"

static apr_status_t json_add_cert_info(md_json_t *json, const md_t *md,
                                       md_cert_t *cert, apr_pool_t *p)
{
    char ts[APR_RFC822_DATE_LEN];
    const char *cert64;
    apr_status_t rv = APR_SUCCESS;
    
    if (cert) {
        apr_rfc822_date(ts, md_cert_get_not_before(cert));
        md_json_sets(ts, json, MD_KEY_VALID_FROM, NULL);
        apr_rfc822_date(ts, md_cert_get_not_after(cert));
        md_json_sets(ts, json, MD_KEY_EXPIRES, NULL);
        md_json_sets(md_cert_get_serial_number(cert, p), json, MD_KEY_SERIAL, NULL);
        if (APR_SUCCESS != (rv = md_cert_to_base64url(&cert64, cert, p))) goto leave;
        md_json_sets(cert64, json, MD_KEY_CERT, NULL);
    }
    else if (md) {
        apr_rfc822_date(ts, md->valid_from);
        md_json_sets(ts, json, MD_KEY_VALID_FROM, NULL);
        apr_rfc822_date(ts, md->expires);
        md_json_sets(ts, json, MD_KEY_EXPIRES, NULL);
        if (md->cert_serial) md_json_sets(md->cert_serial, json, MD_KEY_SERIAL, NULL);
    }
leave:
    return rv;
}

int md_http_cert_status(request_rec *r)
{
    md_store_t *store;
    apr_array_header_t *certs;
    md_cert_t *cert_staged;
    md_json_t *resp, *j;
    const md_srv_conf_t *sc;
    const md_t *md;
    md_t *md_staged;
    apr_bucket_brigade *bb;
    apr_status_t rv;
    
    if (!r->parsed_uri.path || strcmp(MD_STATUS_RESOURCE, r->parsed_uri.path))
        return DECLINED;
        
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "requesting status for: %s", r->hostname);
    
    /* We are looking for information about a staged certificate */
    sc = ap_get_module_config(r->server->module_config, &md_module);
    if (!sc || !sc->mc || !sc->mc->reg) return DECLINED;
    md = md_get_by_domain(sc->mc->mds, r->hostname);
    if (!md) return DECLINED;
    store = md_reg_store_get(sc->mc->reg);
    if (!store) return DECLINED;
    
    if (r->method_number != M_GET) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "md(%s): status supports only GET", md->name);
        return HTTP_NOT_IMPLEMENTED;
    }
    
    resp = md_json_create(r->pool);
    json_add_cert_info(resp, md, NULL, r->pool);
    
    rv = md_load(store, MD_SG_STAGING, md->name, &md_staged, r->pool); 
    if (APR_SUCCESS == rv) {
        j = md_json_create(r->pool);
        md_json_setj(j, resp, "staging", NULL);
        
        cert_staged = NULL;
        rv = md_pubcert_load(store, MD_SG_STAGING, md->name, &certs, r->pool);
        if (APR_SUCCESS == rv && certs->nelts > 0) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, rv, r,
                          "md(%s): adding staged certificate info", md->name);
            cert_staged = APR_ARRAY_IDX(certs, 0, md_cert_t *);
            json_add_cert_info(j, md_staged, cert_staged, r->pool);
        }
        else if (!APR_STATUS_IS_ENOENT(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                          "loading staged certificates for %s", md->name);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, rv, r,
                          "md(%s): no staged certificate", md->name);
        }
    }
    else {
        
    }
    
    apr_table_set(r->headers_out, "Content-Type", "application/json"); 

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    md_json_writeb(resp, MD_JSON_FMT_INDENT, bb);
    ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);
    
    return DONE;
}

/**************************************************************************************************/
/* Status hook */

typedef struct {
    apr_pool_t *p;
    const md_mod_conf_t *mc;
    apr_bucket_brigade *bb;
    const char *separator;
} status_ctx;

typedef struct status_info status_info; 

static void add_json_val(status_ctx *ctx, md_json_t *j);

typedef void add_status_fn(status_ctx *ctx, const md_t *md, const md_drive_job_t *job, 
                    md_json_t *mdj, const status_info *info);

struct status_info {
    const char *label;
    const char *key;
    add_status_fn *fn;
};

static void si_val_status(status_ctx *ctx, const md_t *md, const md_drive_job_t *job, 
                          md_json_t *mdj, const status_info *info)
{
    const char *s = "unknown";
    (void)job;
    (void)mdj;
    (void)info;
    switch (md->state) {
        case MD_S_INCOMPLETE: s = "incomplete"; break;
        case MD_S_EXPIRED_DEPRECATED:
        case MD_S_COMPLETE: s = "ok"; break;
        case MD_S_ERROR: s = "error"; break;
        case MD_S_MISSING: s = "missing information"; break;
        default: break;
    }
    apr_brigade_puts(ctx->bb, NULL, NULL, s);
}

static void si_val_drive_mode(status_ctx *ctx, const md_t *md, const md_drive_job_t *job, 
                              md_json_t *mdj, const status_info *info)
{
    const char *s;
    (void)job;
    (void)md;
    switch (md_json_getl(mdj, info->key, NULL)) {
        case MD_DRIVE_MANUAL: s = "manual"; break;
        case MD_DRIVE_ALWAYS: s = "always"; break;
        default: s = "auto"; break;
    }
    apr_brigade_puts(ctx->bb, NULL, NULL, s);
}


/* currently unused 
static void si_val_timestamp(status_ctx *ctx, apr_time_t timestamp)
{
    if (timestamp > 0) {
        char ts[128];
        apr_time_exp_t texp;
        apr_size_t len;
        
        apr_time_exp_gmt(&texp, timestamp);
        apr_strftime(ts, &len, sizeof(ts)-1, "%Y-%m-%dT%H:%M:%SZ", &texp);
        ts[len] = '\0';
        apr_brigade_puts(ctx->bb, NULL, NULL, ts);
    }
    else {
        apr_brigade_puts(ctx->bb, NULL, NULL, "-");
    }
}
*/

static void si_val_date(status_ctx *ctx, apr_time_t timestamp)
{
    if (timestamp > 0) {
        char ts[128];
        char ts2[128];
        apr_time_exp_t texp;
        apr_size_t len;
        
        apr_time_exp_gmt(&texp, timestamp);
        apr_strftime(ts, &len, sizeof(ts)-1, "%Y-%m-%dT%H:%M:%SZ", &texp);
        ts[len] = '\0';
        apr_strftime(ts2, &len, sizeof(ts2)-1, "%Y-%m-%d", &texp);
        ts2[len] = '\0';
        apr_brigade_printf(ctx->bb, NULL, NULL, 
                           "<span title='%s' style='white-space: nowrap;'>%s</span>", 
                           ts, ts2);
    }
    else {
        apr_brigade_puts(ctx->bb, NULL, NULL, "-");
    }
}

static void si_val_time(status_ctx *ctx, apr_time_t timestamp)
{
    if (timestamp > 0) {
        char ts[128];
        char ts2[128];
        apr_time_exp_t texp;
        apr_size_t len;
        
        apr_time_exp_gmt(&texp, timestamp);
        apr_strftime(ts, &len, sizeof(ts)-1, "%Y-%m-%dT%H:%M:%SZ", &texp);
        ts[len] = '\0';
        apr_strftime(ts2, &len, sizeof(ts2)-1, "%H:%M:%SZ", &texp);
        ts2[len] = '\0';
        apr_brigade_printf(ctx->bb, NULL, NULL, 
                           "<span title='%s' style='white-space: nowrap;'>%s</span>", 
                           ts, ts2);
    }
    else {
        apr_brigade_puts(ctx->bb, NULL, NULL, "-");
    }
}

static void si_val_yes_no(status_ctx *ctx, const md_t *md, const md_drive_job_t *job, 
                          md_json_t *mdj, const status_info *info)
{
    (void)md;
    (void)job;
    apr_brigade_puts(ctx->bb, NULL, NULL, md_json_getl(mdj, info->key, NULL)? "yes" : "no");
}

static void si_val_expires(status_ctx *ctx, const md_t *md, const md_drive_job_t *job, 
                           md_json_t *mdj, const status_info *info)
{
    (void)job;
    (void)mdj;
    (void)info;
    si_val_date(ctx, md->expires);
}

static void si_val_valid_from(status_ctx *ctx, const md_t *md, const md_drive_job_t *job, 
                              md_json_t *mdj, const status_info *info)
{
    (void)job;
    (void)mdj;
    (void)info;
    si_val_date(ctx, md->valid_from);
}
    
static void si_val_props(status_ctx *ctx, const md_t *md, const md_drive_job_t *job, 
                         md_json_t *mdj, const status_info *info)
{
    const char *s;
    int i = 0;
    (void)job;
    (void)mdj;
    (void)info;

    if (md_json_getb(mdj, MD_KEY_MUST_STAPLE, NULL)) {
        ++i;
        apr_brigade_puts(ctx->bb, NULL, NULL, "must-staple");
    }
    s = md_json_gets(mdj, MD_KEY_RENEW_WINDOW, NULL);
    if (s) {
        if (i++) apr_brigade_puts(ctx->bb, NULL, NULL, " \n"); 
        apr_brigade_printf(ctx->bb, NULL, NULL, "renew-at[%s]", s);
    }
    if (md->ca_url) {
        if (i++) apr_brigade_puts(ctx->bb, NULL, NULL, " \n"); 
        s = md->ca_url;
        if (!strcmp(LE_ACMEv2_PROD, s)) s = "letsencrypt(v2)";
        else if (!strcmp(LE_ACMEv1_PROD, s)) s = "letsencrypt(v1)";
        else if (!strcmp(LE_ACMEv2_STAGING, s)) s = "letsencrypt(Testv2)";
        else if (!strcmp(LE_ACMEv1_STAGING, s)) s = "letsencrypt(Testv1)";
        
        apr_brigade_printf(ctx->bb, NULL, NULL, "ca=[<a href=\"%s\">%s</a>]", md->ca_url, s);
    }
    if (md_json_has_key(mdj, MD_KEY_CONTACTS, NULL)) {
        if (i++) apr_brigade_puts(ctx->bb, NULL, NULL, " \n"); 
        apr_brigade_puts(ctx->bb, NULL, NULL, "contacts=[");
        add_json_val(ctx, md_json_getj(mdj, MD_KEY_CONTACTS, NULL));
        apr_brigade_puts(ctx->bb, NULL, NULL, "]");
    }
}
    
static void si_val_renewal(status_ctx *ctx, const md_t *md, const md_drive_job_t *job, 
                           md_json_t *mdj, const status_info *info)
{
    (void)md;
    (void)mdj;
    (void)info;
    if (job) {
        if (job->finished && apr_time_now() >= job->valid_from) {
            apr_brigade_puts(ctx->bb, NULL, NULL, "ready for reload since ");
            si_val_time(ctx, job->valid_from);
        }
        else if (job->finished) {
            apr_brigade_puts(ctx->bb, NULL, NULL, "finished, valid from: ");
            si_val_time(ctx, job->valid_from);
        }
        else if (job->error_runs) {
            apr_brigade_printf(ctx->bb, NULL, NULL, "ongoing, %d errored attempts, next run: ", 
                               job->error_runs);
            si_val_time(ctx, job->next_run);
        }
        else if (job->next_run) {
            apr_brigade_puts(ctx->bb, NULL, NULL, "ongoing, next run: ");
            si_val_time(ctx, job->next_run);
        }
        else {
            apr_brigade_puts(ctx->bb, NULL, NULL, "ongoing");
        }
    }
}

const status_info status_infos[] = {
    { "Name", MD_KEY_NAME, NULL },
    { "Domains", MD_KEY_DOMAINS, NULL },
    { "Status", MD_KEY_STATUS, si_val_status },
    { "Valid", MD_KEY_VALID_FROM, si_val_valid_from },
    { "Expires", MD_KEY_EXPIRES, si_val_expires },
    { "Renew", MD_KEY_DRIVE_MODE, si_val_drive_mode },
    { "Configuration", MD_KEY_MUST_STAPLE, si_val_props },
    { "Status",  MD_KEY_NOTIFIED, si_val_renewal },
};

static int json_iter_val(void *data, size_t index, md_json_t *json)
{
    status_ctx *ctx = data;
    if (index) apr_brigade_puts(ctx->bb, NULL, NULL, ctx->separator);
    add_json_val(ctx, json);
    return 1;
}

static void add_json_val(status_ctx *ctx, md_json_t *j)
{
    if (!j) return;
    else if (md_json_is(MD_JSON_TYPE_ARRAY, j, NULL)) {
        md_json_itera(json_iter_val, ctx, j, NULL);
    }
    else if (md_json_is(MD_JSON_TYPE_INT, j, NULL)) {
        md_json_writeb(j, MD_JSON_FMT_COMPACT, ctx->bb);
    }
    else if (md_json_is(MD_JSON_TYPE_STRING, j, NULL)) {
        apr_brigade_puts(ctx->bb, NULL, NULL, md_json_gets(j, NULL));
    }
    else if (md_json_is(MD_JSON_TYPE_OBJECT, j, NULL)) {
        md_json_writeb(j, MD_JSON_FMT_COMPACT, ctx->bb);
    }
}

static void add_status_cell(status_ctx *ctx, const md_t *md, const md_drive_job_t *job, 
                            md_json_t *mdj, const status_info *info)
{
    if (info->fn) {
        info->fn(ctx, md, job, mdj, info);
    }
    else {
        add_json_val(ctx, md_json_getj(mdj, info->key, NULL));
    }
}

static void add_md_row(status_ctx *ctx, const md_t *md, int index)
{
    md_json_t *mdj;
    md_drive_job_t job, *pjob = NULL;
    int i, renew;
    
    mdj = md_to_json(md, ctx->p);
    renew = md_should_renew(md);
    md_json_setb(renew, mdj, MD_KEY_RENEW, NULL);
    if (renew) {
        
        memset(&job, 0, sizeof(job));
        job.name = md->name;
        if (APR_SUCCESS == md_drive_job_load(&job, ctx->mc->reg, ctx->p)) {
            pjob = &job;
            md_json_setl(job.error_runs, mdj, MD_KEY_ERRORS, NULL);
            md_json_setb(job.notified, mdj, MD_KEY_NOTIFIED, NULL);
        }
    }
    
    apr_brigade_printf(ctx->bb, NULL, NULL, "<tr class=\"%s\">", (index % 2)? "odd" : "even");
    for (i = 0; i < (int)(sizeof(status_infos)/sizeof(status_infos[0])); ++i) {
        apr_brigade_puts(ctx->bb, NULL, NULL, "<td>");
        add_status_cell(ctx, md, pjob, mdj, &status_infos[i]);
        apr_brigade_puts(ctx->bb, NULL, NULL, "</td>");
    }
    apr_brigade_puts(ctx->bb, NULL, NULL, "</tr>");
}

int md_status_hook(request_rec *r, int flags)
{
    const md_srv_conf_t *sc;
    const md_mod_conf_t *mc;
    const md_t *md;
    int i, html;
    status_ctx ctx;
    
    sc = ap_get_module_config(r->server->module_config, &md_module);
    if (!sc) return DECLINED;
    mc = sc->mc;
    if (!mc) return DECLINED;

    html = !(flags & AP_STATUS_SHORT);
    ctx.p = r->pool;
    ctx.mc = mc;
    ctx.bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    ctx.separator = " ";

    if (!html || mc->mds->nelts == 0) {
        apr_brigade_printf(ctx.bb, NULL, NULL, "%sMDomains: %d\n", 
                           html? "<hr>\n" : "", mc->mds->nelts);
    }
    else {
        apr_brigade_puts(ctx.bb, NULL, NULL, 
                         "<hr>\n<h2>Managed Domains</h2>\n<table class='md_status'><thead><tr>\n");
        for (i = 0; i < (int)(sizeof(status_infos)/sizeof(status_infos[0])); ++i) {
            apr_brigade_puts(ctx.bb, NULL, NULL, "<th>");
            apr_brigade_puts(ctx.bb, NULL, NULL, status_infos[i].label);
            apr_brigade_puts(ctx.bb, NULL, NULL, "</th>");
        }
        apr_brigade_puts(ctx.bb, NULL, NULL, "</tr>\n</thead><tbody>");
        for (i = 0; i < mc->mds->nelts; ++i) {
            md = APR_ARRAY_IDX(mc->mds, i, const md_t *);
            add_md_row(&ctx, md, i);
        }
        apr_brigade_puts(ctx.bb, NULL, NULL, "</td></tr>\n</tbody>\n</table>\n");
    }

    ap_pass_brigade(r->output_filters, ctx.bb);
    apr_brigade_cleanup(ctx.bb);
    
    return OK;
}

