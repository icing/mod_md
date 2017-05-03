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

#include "mod_md.h"
#include "md_version.h"

static void md_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(md) = {
    STANDARD20_MODULE_STUFF,
    NULL, /*md_config_create_dir,*/ /* func to create per dir config */
    NULL, /*md_config_merge_dir,*/  /* func to merge per dir config */
    NULL, /*md_config_create_svr,*/ /* func to create per server config */
    NULL, /*md_config_merge_svr,*/  /* func to merge per server config */
    NULL, /*md_cmds,*/              /* command handlers */
    md_hooks
};

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
static int md_post_config(apr_pool_t *p, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    const char *mod_md_init_key = "mod_md_init_counter";
    
    (void)plog;(void)ptemp;
    
    apr_pool_userdata_get(&data, mod_md_init_key, s->process->pool);
    if ( data == NULL ) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                     "initializing post config dry run");
        apr_pool_userdata_set((const void *)1, mod_md_init_key,
                              apr_pool_cleanup_null, s->process->pool);
        return APR_SUCCESS;
    }
    
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO()
                 "mod_md (v%s), initializing...", MOD_MD_VERSION);
    
    return APR_SUCCESS;
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
    
    /* Run once after configuration is set, but before mpm children initialize.
     */
    ap_hook_post_config(md_post_config, mod_ssl, NULL, APR_HOOK_MIDDLE);
    
    /* Run once after a child process has been created.
     */
    ap_hook_child_init(md_child_init, NULL, NULL, APR_HOOK_MIDDLE);

}
