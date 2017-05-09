/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
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

#include <apr_strings.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_vhost.h>

#include "md.h"
#include "mod_md.h"
#include "md_config.h"
#include "md_version.h"

static void md_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(md) = {
    STANDARD20_MODULE_STUFF,
    NULL, /* func to create per dir config */
    NULL, /* func to merge per dir config */
    md_config_create_svr, /* func to create per server config */
    md_config_merge_svr,  /* func to merge per server config */
    md_cmds,              /* command handlers */
    md_hooks
};


static md_ca_t *find_or_add_ca(apr_array_header_t *cas, const md_config *config,
                               apr_pool_t *p)
{
    md_ca_t *ca = NULL, **pca;
    const char *url = md_config_var_get(config, MD_CONFIG_CA_URL);
    const char *proto = md_config_var_get(config, MD_CONFIG_CA_PROTO);
    int i;
    
    ap_assert(url);
    ap_assert(proto);
    
    for (i = 0; i < cas->nelts; ++i) {
        ca = APR_ARRAY_IDX(cas, i, md_ca_t*);
        if (strcmp(url, ca->url) == 0 && strcmp(proto, ca->proto) == 0) {
            return ca;
        }
    }
    
    ca = apr_pcalloc(p, sizeof(*ca));
    ca->url = url;
    ca->proto = proto;
    pca= (md_ca_t **)apr_array_push(cas);
    *pca = ca;

    return ca;
}

/* The module initialization. Called once as apache hook, before any multi
 * processing (threaded or not) happens. It is typically at least called twice, 
 * see
 * http://wiki.apache.org/httpd/ModuleLife
 * Since the first run is just a "practise" run, we want to initialize for real
 * only on the second try. This defeats the purpose of the first dry run a bit, 
 * since apache wants to verify that a new configuration actually will work. 
 * So if we have trouble with the configuration, this will only be detected 
 * when the server has already switched.
 * On the other hand, when we initialize lib nghttp2, all possible crazy things 
 * might happen and this might even eat threads. So, better init on the real 
 * invocation, for now at least.
 */
static apr_status_t md_post_config(apr_pool_t *p, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *base_server)
{
    void *data = NULL;
    const char *mod_md_init_key = "mod_md_init_counter";
    server_rec *s;
    md_config *config;
    apr_array_header_t *mds;
    apr_array_header_t *cas;
    int i, j, k;
    md_t *md, *nmd, **pmd;
    const char *domain, *name;
    request_rec r;
    apr_status_t status = APR_SUCCESS;
    
    (void)plog;(void)ptemp;
    
    apr_pool_userdata_get(&data, mod_md_init_key, base_server->process->pool);
    if ( data == NULL ) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO()
                     "initializing post config dry run");
        apr_pool_userdata_set((const void *)1, mod_md_init_key,
                              apr_pool_cleanup_null, base_server->process->pool);
        return APR_SUCCESS;
    }
    
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, base_server, APLOGNO()
                 "mod_md (v%s), initializing...", MOD_MD_VERSION);

    /*
     * Collect all defined Managed Domains, check for uniqueness
     * and compile the global list.
     */
    mds = apr_array_make(p, 5, sizeof(const md_t *));
    cas = apr_array_make(p, 5, sizeof(const md_ca_t *));
    for (s = base_server; s; s = s->next) {
        config = (md_config *)md_config_sget(s);
        
        for (i = 0; i < config->mds->nelts; ++i) {
            nmd = APR_ARRAY_IDX(config->mds, i, md_t*);
            for (j = 0; j < mds->nelts; ++j) {
                md = APR_ARRAY_IDX(mds, j, md_t*);
                if (nmd == md) {
                    nmd = NULL;
                    break; /* merged between different configs */
                }
                if ((domain = md_common_name(nmd, md)) != NULL) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO()
                                 "two Managed Domains have an overlap in domain '%s'"
                                 ", first definition in %s(line %d), second in %s(line %d)",
                                 domain, md->defn_name, md->defn_line_number,
                                 nmd->defn_name, nmd->defn_line_number);
                    return APR_EINVAL;
                }
            }
            
            if (nmd) {
                /* new managed domain not seen before */
                nmd->ca = find_or_add_ca(cas, config, p);
                pmd = (md_t **)apr_array_push(mds);
                *pmd = nmd;
            }
        }
        
        /* set the aggregated md_t list into each config, so there is access
         * to it from severy server_rec */
        config->mds = mds;
    }
    
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server, APLOGNO()
                 "found %d Managed Domains against %d CAs in configuration",
                 mds->nelts, cas->nelts);
                 
    memset(&r, 0, sizeof(r));
    for (i = 0; i < mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mds, i, md_t*);
        config = NULL;
        for (s = base_server; s; s = s->next) {
            r.server = s;
            /* try finding a matching server for the domain, might be more than  one */ 
            for (j = 0; j < md->domains->nelts; ++j) {
                domain = APR_ARRAY_IDX(md->domains, j, const char*);
                
                if (ap_matches_request_vhost(&r, domain, s->port)) {
                    config = (md_config *)md_config_sget(s);
                    if (config->emd == md) {
                        /* already matched via another domain name */
                    }
                    else if (config->emd) {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO()
                                     "Managed Domain %s matches server %s, but MD %s also matches",
                                     md->name, s->server_hostname, config->emd->name);
                        status = APR_EINVAL;
                    }
                    /* This server matches a managed domain. If it contains names or
                     * alias that are not in this md, a generated certificate will not match.
                     */
                    if (!md_contains(md, s->server_hostname)) {
                        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO()
                                     "Virtual Host %s:%d matches Managed Domain %s, but the name"
                                     " itself is not managed. A requested MD certificate will "
                                     "not match ServerName.",
                                     s->server_hostname, s->port, md->name);
                    }
                    else {
                        for (k = 0; k < s->names->nelts; ++k) {
                            name = APR_ARRAY_IDX(s->names, k, const char*);
                            if (!md_contains(md, name)) {
                                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO()
                                             "Virtual Host %s:%d matches Managed Domain %s, but "
                                             "the ServerAlias %s is not covered by the MD. "
                                             "A requested MD certificate will not match this " 
                                             "alias.", s->server_hostname, s->port, md->name,
                                             name);
                            }
                        }
                    }
                    config->emd = md;
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server, APLOGNO()
                                 "Managed Domain %s applies to vhost %s:%d", md->name,
                                 s->server_hostname, s->port);
                    break;
                }
            }
        }
        
        if (config == NULL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO()
                         "No VirtualHost matches Managed Domain %s", md->name);
        }
    }
    
    return status;
}

/* Runs once per created child process. Perform any process 
 * related initionalization here.
 */
static void md_child_init(apr_pool_t *pool, server_rec *s)
{
}

/* Install this module into the apache2 infrastructure.
 */
static void md_hooks(apr_pool_t *pool)
{
    static const char *const mod_ssl[] = { "mod_ssl.c", NULL};
    
    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks");
    
    /* Run once after configuration is set, before mod_ssl.
     */
    ap_hook_post_config(md_post_config, NULL, mod_ssl, APR_HOOK_MIDDLE);
    
    /* Run once after a child process has been created.
     */
    ap_hook_child_init(md_child_init, NULL, NULL, APR_HOOK_MIDDLE);

}
