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

#include <assert.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_vhost.h>

#include "md.h"
#include "mod_md.h"
#include "md_config.h"
#include "md_store.h"
#include "md_util.h"
#include "md_version.h"
#include "acme/md_acme_authz.h"

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


static apr_status_t md_calc_md_list(apr_pool_t *p, apr_pool_t *plog,
                                    apr_pool_t *ptemp, server_rec *base_server,
                                    apr_array_header_t **pmds)
{
    server_rec *s;
    apr_array_header_t *mds;
    int i, j;
    md_t *md, *nmd;
    const char *domain;
    apr_status_t rv = APR_SUCCESS;
    md_config_t *config;

    mds = apr_array_make(p, 5, sizeof(const md_t *));
    for (s = base_server; s; s = s->next) {
        config = (md_config_t *)md_config_sget(s);
        
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
                nmd->ca_url = md_config_var_get(config, MD_CONFIG_CA_URL);
                nmd->ca_proto = md_config_var_get(config, MD_CONFIG_CA_PROTO);
                APR_ARRAY_PUSH(mds, md_t *) = nmd;
            }
        }
    }
    *pmds = (APR_SUCCESS == rv)? mds : NULL;
    return rv;
}

static apr_status_t md_check_vhost_mapping(apr_pool_t *p, apr_pool_t *plog,
                                           apr_pool_t *ptemp, server_rec *base_server,
                                           apr_array_header_t *mds)
{
    server_rec *s;
    request_rec r;
    md_config_t *config;
    apr_status_t rv = APR_SUCCESS;
    md_t *md;
    int i, j, k;
    const char *domain, *name;
    
    memset(&r, 0, sizeof(r));
    for (i = 0; i < mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mds, i, md_t*);
        config = NULL;
        for (s = base_server; s; s = s->next) {
            r.server = s;
            
            if (strcmp(ap_http_scheme(&r), "https")) {
                /* Not a TLS enabled server */
                continue;
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO()
                         "Server %s:%d uses https", s->server_hostname, s->port);
            
            /* try finding a matching server for the domain, might be more than  one */ 
            for (j = 0; j < md->domains->nelts; ++j) {
                domain = APR_ARRAY_IDX(md->domains, j, const char*);
                
                if (ap_matches_request_vhost(&r, domain, s->port)) {
                
                    config = (md_config_t *)md_config_sget(s);
                    if (config->emd == md) {
                        /* already matched via another domain name */
                    }
                    else if (config->emd) {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO()
                                     "Managed Domain %s matches server %s, but MD %s also matches.",
                                     md->name, s->server_hostname, config->emd->name);
                        rv = APR_EINVAL;
                    }
                    /* This server matches a managed domain. If it contains names or
                     * alias that are not in this md, a generated certificate will not match.
                     */
                    if (!md_contains(md, s->server_hostname)) {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO()
                                     "Virtual Host %s:%d matches Managed Domain %s, but the name"
                                     " itself is not managed. A requested MD certificate will "
                                     "not match ServerName.",
                                     s->server_hostname, s->port, md->name);
                        rv = APR_EINVAL;
                    }
                    else {
                        for (k = 0; k < s->names->nelts; ++k) {
                            name = APR_ARRAY_IDX(s->names, k, const char*);
                            if (!md_contains(md, name)) {
                                ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO()
                                             "Virtual Host %s:%d matches Managed Domain %s, but "
                                             "the ServerAlias %s is not covered by the MD. "
                                             "A requested MD certificate will not match this " 
                                             "alias.", s->server_hostname, s->port, md->name,
                                             name);
                                rv = APR_EINVAL;
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
    return rv;
}

static apr_status_t setup_store(md_store_t **pstore, apr_pool_t *p, server_rec *s)
{
    const char *base_dir;
    md_config_t *config;
    md_store_t *store;
    apr_status_t rv;
    
    config = (md_config_t *)md_config_sget(s);
    base_dir = md_config_var_get(config, MD_CONFIG_BASE_DIR);
    base_dir = ap_server_root_relative(p, base_dir);
    
    rv = md_store_fs_init(&store, p, base_dir, 1);
    
    if (APR_SUCCESS == rv) {
        config->store = store;
        
        for (s = s->next; s; s = s->next) {
            config = (md_config_t *)md_config_sget(s);
            config->store = store;
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                     "setup store for %s", base_dir);
    }
    *pstore = (APR_SUCCESS == rv)? store : NULL;
    return rv;
}

static apr_status_t md_store_sync(md_store_t *store, apr_pool_t *p, apr_pool_t *ptemp, 
                                  apr_array_header_t *mds, server_rec *s) 
{
    apr_array_header_t *store_mds;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = md_load_all(&store_mds, store, ptemp))) {
        int i;
        md_t *md, *config_md, *smd, *omd;
        const char *common;
        
        for (i = 0; i < mds->nelts; ++i) {
            md = APR_ARRAY_IDX(mds, i, md_t *);
            smd = md_get_by_name(store_mds, md->name);
            
            while (APR_SUCCESS == rv && (omd = md_get_by_dns_overlap(store_mds, md))) {
                common = md_common_name(md, omd);
                assert(common);
                config_md = md_get_by_name(mds, omd->name);
                if (config_md && md_contains(config_md, common)) {
                    /* domain used in two configured mds, not allowed */
                    rv = APR_EINVAL;
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO()
                                 "domain %s used in md %s and %s", common, md->name, omd->name);
                }
                else if (config_md) {
                    /* domain stored in omd, but no longer configured so */
                    omd->domains = md_array_str_remove(ptemp, omd->domains, common, 0);
                    rv = md_save(store, omd, 0);
                }
                else {
                    /* domain stored in omd, but omd no longer configured */
                    rv = APR_EINVAL;
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO()
                                 "domain %s, configured in md %s, is part of the stored md %s. "
                                 "That md however is no longer mentioned in the config. "
                                 "If you longer want it, remove the md from the store.", 
                                 common, md->name, omd->name);
                }
            }

            if (APR_SUCCESS == rv) {
                if (smd) {
                    int added;
                    
                    /* existing managed domain, update necessary? */
                    added = md_array_str_add_missing(smd->domains, md->domains, 0);
                    if (added) {
                        rv = md_save(store, md, 0);
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO() 
                                     "md %s updated with %d additional domains", md->name, added);
                    } 
                }
                else {
                    /* new managed domain */
                    rv = md_save(store, md, 1);
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO() 
                                 "new md %s saved", md->name);
                }
            }
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO() "loading mds");
    }
    
    return rv;
}

/*
 * Config has been loaded completely for the given base server. Now,
 * before the actual request processing starts, is the time to prepare
 * everything based on this. Also, this is the last chance to fail the config.
 *
 * The following is done:
 * 1. Collect all defined "managed domains" (MD). Since DNS is one thing, it does
 *    not matter where a MD is defined. All MDs need to be unique and have no overlaps
 *    in their DNS names. Fail the config otherwise. Also, if a vhost matches an MD, it
 *    needs to *only* have ServerAliases from that MD. There can be no more than one
 *    matching MD for a vhost. But an MD can apply to several vhosts.
 * 2. Instantiate the Store. Iterator over all defined domains and 
 *   a. create them in the store if they do not already exist
 *   b. compare dns lists from store and config, if
 *      - store has dns name in other MD than from config, remove dns name from store def,
 *        issue WARNING. TODO: what if this was the last name???
 *      - store misses dns name from config, add dns name to store def
 *      - store misses MD, create it 
 *   c. compare MD acme url/protocol, update if changed
 *   
 */
static apr_status_t md_post_config(apr_pool_t *p, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *base_server)
{
    void *data = NULL;
    const char *mod_md_init_key = "mod_md_init_counter";
    apr_array_header_t *mds;
    md_store_t *store;
    apr_status_t rv = APR_SUCCESS;

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

    /* 1. Check uniqueness of MDs, calculate global MD list */
    if (APR_SUCCESS == (rv = md_calc_md_list(p, plog, ptemp, base_server, &mds))) {
        /* Check mappings of MDs to VirtulHosts defined */
        rv = md_check_vhost_mapping(p, plog, ptemp, base_server, mds);    

        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, base_server, APLOGNO()
                     "checked %d Managed Domains", mds->nelts);
    }

    /* 2. If config consistent, sync with store */
    if (APR_SUCCESS == (rv = setup_store(&store, p, base_server))) {
        rv = md_store_sync(store, p, ptemp, mds, base_server);
    }
     
    return rv;
}

#define ACME_CHALLENGE_PREFIX       "/.well-known/acme-challenge/"

static int md_http_challenge_pr(request_rec *r)
{
    apr_bucket_brigade *bb;
    const md_config_t *conf;
    const char *base_dir, *name, *data;
    apr_status_t rv;
            
    if (r->method_number == M_GET) {
        if (!strncmp(ACME_CHALLENGE_PREFIX, r->parsed_uri.path, sizeof(ACME_CHALLENGE_PREFIX)-1)) {
            conf = ap_get_module_config(r->server->module_config, &md_module);
            base_dir = md_config_var_get(conf, MD_CONFIG_BASE_DIR);
            name = r->parsed_uri.path + sizeof(ACME_CHALLENGE_PREFIX)-1;

            r->status = HTTP_NOT_FOUND;
            if (!strchr(name, '/') && conf->store) {
                base_dir = ap_server_root_relative(r->pool, base_dir);
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                              "Challenge for %s (%s) -> %s (%s)", 
                              r->hostname, r->uri, base_dir, name);

                rv = md_store_load(conf->store, MD_SG_CHALLENGES, r->hostname, 
                                   MD_FN_HTTP01, MD_SV_TEXT, (void**)&data, r->pool);
                if (APR_SUCCESS == rv) {
                    apr_size_t len = strlen(data);
                    
                    r->status = HTTP_OK;
                    apr_table_setn(r->headers_out, "Content-Length", apr_ltoa(r->pool, (long)len));
                    
                    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
                    apr_brigade_write(bb, NULL, NULL, data, len);
                    ap_pass_brigade(r->output_filters, bb);
                    apr_brigade_cleanup(bb);
                }
                else if (APR_ENOENT != rv) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                                  "loading challenge %s from store %s", name, base_dir);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            return r->status;
        }
    }
    return DECLINED;
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

    /* answer challenges *very* early, before any configured authentication may strike */
    ap_hook_post_read_request(md_http_challenge_pr, NULL, NULL, APR_HOOK_MIDDLE);
}
