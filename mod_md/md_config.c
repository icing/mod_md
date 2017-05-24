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

#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_vhost.h>

#include "md.h"
#include "md_config.h"
#include "md_util.h"
#include "md_private.h"


#define DEF_VAL     (-1)

static md_config defconf = {
    "default",
    NULL,
    "https://acme-v01.api.letsencrypt.org/directory",
    "ACME",
    NULL
};

static void *md_config_create(apr_pool_t *pool,
                              const char *prefix, const char *x)
{
    md_config *conf = (md_config *)apr_pcalloc(pool, sizeof(md_config));
    const char *s = x? x : "unknown";

    conf->name = apr_pstrcat(pool, prefix, "[", s, "]", NULL);
    conf->mds = apr_array_make(pool, 5, sizeof(const md_t *));

    return conf;
}

void *md_config_create_svr(apr_pool_t *pool, server_rec *s)
{
    return md_config_create(pool, "srv", s->defn_name);
}

static void *md_config_merge(apr_pool_t *pool, void *basev, void *addv)
{
    md_config *base = (md_config *)basev;
    md_config *add = (md_config *)addv;
    md_config *n = (md_config *)apr_pcalloc(pool, sizeof(md_config));
    char *name = apr_pstrcat(pool, "merged[", add->name, ", ", base->name, "]", NULL);
    md_t *md, **pmd;
    int i;
    
    n->name = name;

    /* I think we should not merge md definitions. They should reside where
     * they were defined */
    n->mds = apr_array_make(pool, add->mds->nelts, sizeof(const md_t *));
    for (i = 0; i < add->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(add->mds, i, md_t*);
        pmd = (md_t **)apr_array_push(n->mds);
        *pmd = md_clone(pool, md);
    }
    n->ca_url = add->ca_url? add->ca_url : base->ca_url;
    n->ca_proto = add->ca_proto? add->ca_proto : base->ca_proto;
    n->emd = add->emd? add->emd : base->emd;
    
    return n;
}

void *md_config_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    return md_config_merge(pool, basev, addv);
}

static const char *md_config_set_names(cmd_parms *parms, void *arg, 
                                       int argc, char *const argv[])
{
    md_config *config = (md_config *)md_config_sget(parms->server);
    apr_array_header_t *domains = apr_array_make(parms->pool, 5, sizeof(const char *));
    const char *err, *name, **np;
    md_t *md, **pmd;
    int i;

    err = ap_check_cmd_context(parms, NOT_IN_DIR_LOC_FILE);
    if (err) {
        return err;
    }
    
    for (i = 0; i < argc; ++i) {
        name = argv[i];
        if (md_array_str_case_index(domains, name, 0) < 0) {
            np = (const char **)apr_array_push(domains);
            md_util_str_tolower(apr_pstrdup(parms->pool, name));
            *np = name;
        }
    }
    err = md_create(&md, parms->pool, domains);
    if (err) {
        return err;
    }
    
    if (parms->config_file) {
        md->defn_name = parms->config_file->name;
        md->defn_line_number = parms->config_file->line_number;
    }

    pmd = (md_t **)apr_array_push(config->mds);
    *pmd = md;

    return NULL;
}

static const char *md_config_set_ca(cmd_parms *parms,
                                    void *arg, const char *value)
{
    md_config *config = (md_config *)md_config_sget(parms->server);
    const char *err = ap_check_cmd_context(parms, NOT_IN_DIR_LOC_FILE);

    if (err) {
        return err;
    }
    config->ca_url = value;
    (void)arg;
    return NULL;
}

static const char *md_config_set_ca_proto(cmd_parms *parms,
                                          void *arg, const char *value)
{
    md_config *config = (md_config *)md_config_sget(parms->server);
    const char *err = ap_check_cmd_context(parms, NOT_IN_DIR_LOC_FILE);

    if (err) {
        return err;
    }
    config->ca_proto = value;
    (void)arg;
    return NULL;
}

#define AP_END_CMD     AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)

const command_rec md_cmds[] = {
    AP_INIT_TAKE_ARGV("ManagedDomains", md_config_set_names, NULL, RSRC_CONF | EXEC_ON_READ, 
                      "A group of domain names with one certificate"),
    AP_INIT_TAKE1("MDCertificateAuthority", md_config_set_ca, NULL, RSRC_CONF, 
                  "URL of CA issueing the certificates"),
    AP_INIT_TAKE1("MDCertificateProtocol", md_config_set_ca_proto, NULL, RSRC_CONF, 
                  "Protocol used to obtain/renew certificates"),
    AP_END_CMD
};


const md_config *md_config_sget(server_rec *s)
{
    md_config *cfg = (md_config *)ap_get_module_config(s->module_config, 
                                                       &md_module);
    ap_assert(cfg);
    return cfg;
}

const md_config *md_config_get(conn_rec *c)
{
    return md_config_sget(c->base_server);
}

const char *md_config_var_get(const md_config *config, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_CA_URL:
            return config->ca_url? config->ca_url : defconf.ca_url;
        case MD_CONFIG_CA_PROTO:
            return config->ca_proto? config->ca_proto : defconf.ca_proto;
    }
    return NULL;
}
