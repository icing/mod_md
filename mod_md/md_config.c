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

static md_config_t defconf = {
    "default",
    NULL,
    NULL,
    "https://acme-v01.api.letsencrypt.org/directory",
    "ACME",
    NULL, 
    MD_DRIVE_AUTO, 
    NULL, 
    "md",
    NULL
};

#define CONF_S_NAME(s)  (s && s->server_hostname? s->server_hostname : "default")

void *md_config_create_svr(apr_pool_t *pool, server_rec *s)
{
    md_config_t *conf = (md_config_t *)apr_pcalloc(pool, sizeof(md_config_t));

    conf->name = apr_pstrcat(pool, "srv[", CONF_S_NAME(s), "]", NULL);
    conf->s = s;
    conf->drive_mode = DEF_VAL;
    conf->mds = apr_array_make(pool, 5, sizeof(const md_t *));

    return conf;
}

static void *md_config_merge(apr_pool_t *pool, void *basev, void *addv)
{
    md_config_t *base = (md_config_t *)basev;
    md_config_t *add = (md_config_t *)addv;
    md_config_t *n = (md_config_t *)apr_pcalloc(pool, sizeof(md_config_t));
    char *name = apr_pstrcat(pool, "[", CONF_S_NAME(add->s), ", ", CONF_S_NAME(base->s), "]", NULL);
    md_t *md;
    int i;
    
    n->name = name;

    /* I think we should not merge md definitions. They should reside where
     * they were defined */
    n->mds = apr_array_make(pool, add->mds->nelts, sizeof(const md_t *));
    for (i = 0; i < add->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(add->mds, i, md_t*);
        APR_ARRAY_PUSH(n->mds, md_t *) = md_clone(pool, md);
    }
    n->ca_url = add->ca_url? add->ca_url : base->ca_url;
    n->ca_proto = add->ca_proto? add->ca_proto : base->ca_proto;
    n->ca_agreement = add->ca_agreement? add->ca_agreement : base->ca_agreement;
    n->drive_mode = (add->drive_mode == DEF_VAL)? add->drive_mode : base->drive_mode;
    n->md = NULL;
    n->base_dir = add->base_dir? add->base_dir : base->base_dir;
    return n;
}

void *md_config_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    return md_config_merge(pool, basev, addv);
}

static const char *md_config_set_names(cmd_parms *parms, void *arg, 
                                       int argc, char *const argv[])
{
    md_config_t *config = (md_config_t *)md_config_get(parms->server);
    apr_array_header_t *domains = apr_array_make(parms->pool, 5, sizeof(const char *));
    const char *err, *name;
    md_t *md;
    int i;

    err = ap_check_cmd_context(parms, NOT_IN_DIR_LOC_FILE);
    if (err) {
        return err;
    }
    
    for (i = 0; i < argc; ++i) {
        name = argv[i];
        if (md_array_str_index(domains, name, 0, 0) < 0) {
            APR_ARRAY_PUSH(domains, char *) = md_util_str_tolower(apr_pstrdup(parms->pool, name));
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

    APR_ARRAY_PUSH(config->mds, md_t *) = md;

    return NULL;
}

static const char *md_config_set_ca(cmd_parms *parms, void *arg, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(parms->server);
    const char *err = ap_check_cmd_context(parms, NOT_IN_DIR_LOC_FILE);

    if (err) {
        return err;
    }
    config->ca_url = value;
    (void)arg;
    return NULL;
}

static const char *md_config_set_ca_proto(cmd_parms *parms, void *arg, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(parms->server);
    const char *err = ap_check_cmd_context(parms, NOT_IN_DIR_LOC_FILE);

    if (err) {
        return err;
    }
    config->ca_proto = value;
    (void)arg;
    return NULL;
}

static const char *md_config_set_agreement(cmd_parms *parms, void *arg, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(parms->server);
    const char *err = ap_check_cmd_context(parms, NOT_IN_DIR_LOC_FILE);

    if (err) {
        return err;
    }
    config->ca_agreement = value;
    (void)arg;
    return NULL;
}

static const char *md_config_set_store_dir(cmd_parms *parms, void *arg, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(parms->server);
    const char *err = ap_check_cmd_context(parms, GLOBAL_ONLY);

    if (err) {
        return err;
    }
    config->base_dir = value;
    (void)arg;
    return NULL;
}

static const char *md_config_set_drive_mode(cmd_parms *parms, void *arg, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(parms->server);
    const char *err = ap_check_cmd_context(parms, GLOBAL_ONLY);

    if (err) {
        return err;
    }
    if (!apr_strnatcasecmp("auto", value) || !apr_strnatcasecmp("automatic", value)) {
        config->drive_mode = MD_DRIVE_AUTO;
    }
    else if (!apr_strnatcasecmp("manual", value) || !apr_strnatcasecmp("stick", value)) {
        config->drive_mode = MD_DRIVE_MANUAL;
    }
    (void)arg;
    return NULL;
}

#define AP_END_CMD     AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)

const command_rec md_cmds[] = {
    AP_INIT_TAKE_ARGV("ManagedDomain", md_config_set_names, NULL, RSRC_CONF | EXEC_ON_READ, 
                      "A group of server names with one certificate"),
    AP_INIT_TAKE1("MDCertificateAuthority", md_config_set_ca, NULL, RSRC_CONF, 
                  "URL of CA issueing the certificates"),
    AP_INIT_TAKE1("MDStoreDir", md_config_set_store_dir, NULL, RSRC_CONF, 
                  "the directory for file system storage of managed domain data."),
    AP_INIT_TAKE1("MDCertificateProtocol", md_config_set_ca_proto, NULL, RSRC_CONF, 
                  "Protocol used to obtain/renew certificates"),
    AP_INIT_TAKE1("MDCertificateAgreement", md_config_set_agreement, NULL, RSRC_CONF, 
                  "URL of CA Terms-of-Service agreement you accept"),
    AP_INIT_TAKE1("MDDriveMode", md_config_set_drive_mode, NULL, RSRC_CONF, 
                  "method of obtaining certificates for the managed domain"),
    AP_END_CMD
};


static const md_config_t *config_get_int(server_rec *s, apr_pool_t *p)
{
    md_config_t *cfg = (md_config_t *)ap_get_module_config(s->module_config, &md_module);
    ap_assert(cfg);
    if (cfg->s != s && p) {
        cfg = md_config_merge(p, &defconf, cfg);
        cfg->name = apr_pstrcat(p, CONF_S_NAME(s), cfg->name, NULL);
        ap_set_module_config(s->module_config, &md_module, cfg);
    }
    return cfg;
}

const md_config_t *md_config_get(server_rec *s)
{
    return config_get_int(s, NULL);
}

const md_config_t *md_config_get_unique(server_rec *s, apr_pool_t *p)
{
    assert(p);
    return config_get_int(s, p);
}

const md_config_t *md_config_cget(conn_rec *c)
{
    return md_config_get(c->base_server);
}

const char *md_config_gets(const md_config_t *config, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_CA_URL:
            return config->ca_url? config->ca_url : defconf.ca_url;
        case MD_CONFIG_CA_PROTO:
            return config->ca_proto? config->ca_proto : defconf.ca_proto;
        case MD_CONFIG_BASE_DIR:
            return config->base_dir? config->base_dir : defconf.base_dir;
        case MD_CONFIG_CA_AGREEMENT:
            return config->ca_agreement? config->ca_agreement : defconf.ca_agreement;
        default:
            return NULL;
    }
}

int md_config_geti(const md_config_t *config, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_DRIVE_MODE:
            return (config->drive_mode != DEF_VAL)? config->drive_mode : defconf.drive_mode;
        default:
            return 0;
    }
}
