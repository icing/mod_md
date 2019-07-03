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
#include <apr_time.h>
#include <apr_date.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "mod_watchdog.h"

#include "md.h"
#include "md_crypt.h"
#include "md_http.h"
#include "md_json.h"
#include "md_ocsp.h"
#include "md_store.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_time.h"
#include "md_util.h"

#include "mod_md.h"
#include "mod_md_config.h"
#include "mod_md_private.h"
#include "mod_md_ocsp.h"

static int staple_here(md_srv_conf_t *sc) 
{
    if (!sc || !sc->mc->ocsp) return 0;
    if (sc->assigned) return sc->assigned->stapling;
    return (md_config_geti(sc, MD_CONFIG_STAPLING) 
            && md_config_geti(sc, MD_CONFIG_STAPLE_OTHERS));
}

apr_status_t md_ocsp_init_stapling_status(server_rec *s, apr_pool_t *p, 
                                          void *x509cert, void *x509issuer)
{
    md_srv_conf_t *sc;
    const md_t *md;

    sc = md_config_get(s);
    if (!staple_here(sc)) goto declined;
    
    md = sc->assigned;
    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, s, "init stapling for: %s", 
                 md? md->name : s->server_hostname);
    return md_ocsp_prime(sc->mc->ocsp, md_cert_wrap(p, x509cert), 
                         md_cert_wrap(p, x509issuer), md);
declined:
    return DECLINED;
}

apr_status_t md_ocsp_get_stapling_status(unsigned char **pder, int *pderlen, 
                                         conn_rec *c, server_rec *s, void *x509cert)
{
    md_srv_conf_t *sc;
    const md_t *md;
    apr_status_t rv;
    
    sc = md_config_get(s);
    if (!staple_here(sc)) goto declined;

    md = sc->assigned;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, "get stapling for: %s", 
                  md? md->name : s->server_hostname);
    rv = md_ocsp_get_status(pder, pderlen, sc->mc->ocsp, 
                            md_cert_wrap(c->pool, x509cert), c->pool, md);
    if (APR_STATUS_IS_ENOENT(rv)) goto declined;
    return rv;
    
declined:
    return DECLINED;
}
                          
/**************************************************************************************************/
/* watchdog based impl. */

#define MD_OCSP_WATCHDOG_NAME   "_md_ocsp_"

static APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *wd_get_instance;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *wd_register_callback;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_set_callback_interval) *wd_set_interval;

typedef struct md_ocsp_ctx_t md_ocsp_ctx_t;

struct md_ocsp_ctx_t {
    apr_pool_t *p;
    server_rec *s;
    md_mod_conf_t *mc;
    ap_watchdog_t *watchdog;
    
    const md_timeslice_t *renew_window;
};

static apr_time_t next_run_default(void)
{
    /* we'd like to run at least hourly */
    return apr_time_now() + apr_time_from_sec(MD_SECS_PER_HOUR);
}

static apr_status_t run_watchdog(int state, void *baton, apr_pool_t *ptemp)
{
    md_ocsp_ctx_t *octx = baton;
    apr_time_t next_run, wait_time;
    
    /* mod_watchdog invoked us as a single thread inside the whole server (on this machine).
     * This might be a repeated run inside the same child (mod_watchdog keeps affinity as
     * long as the child lives) or another/new child.
     */
    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, octx->s, APLOGNO()
                         "md ocsp watchdog start, ocsp stapling %d certificates", 
                         (int)md_ocsp_count(octx->mc->ocsp));
            break;
            
        case AP_WATCHDOG_STATE_RUNNING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, octx->s, APLOGNO()
                         "md ocsp watchdog run, ocsp stapling %d certificates", 
                         (int)md_ocsp_count(octx->mc->ocsp));
                         
            /* Process all drive jobs. They will update their next_run property
             * and we schedule ourself at the earliest of all. A job may specify 0
             * as next_run to indicate that it wants to participate in the normal
             * regular runs. */
            next_run = next_run_default();
            
            md_ocsp_renew(octx->mc->ocsp, octx->renew_window, octx->p, ptemp, &next_run);
            
            wait_time = next_run - apr_time_now();
            if (APLOGdebug(octx->s)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, octx->s, APLOGNO()
                             "md ocsp watchdog next run in %s", 
                             md_duration_print(ptemp, wait_time));
            }
            wd_set_interval(octx->watchdog, wait_time, octx, run_watchdog);
            break;
            
        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, octx->s, APLOGNO()
                         "md ocsp watchdog stopping");
            break;
    }
    
    return APR_SUCCESS;
}

apr_status_t md_ocsp_start_watching(struct md_mod_conf_t *mc, server_rec *s, apr_pool_t *p)
{
    apr_allocator_t *allocator;
    md_ocsp_ctx_t *octx;
    apr_pool_t *octxp;
    apr_status_t rv;
    
    wd_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    wd_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    wd_set_interval = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_set_callback_interval);
    
    if (!wd_get_instance || !wd_register_callback || !wd_set_interval) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO() 
                     "mod_watchdog is required for OCSP stapling");
        return APR_EGENERAL;
    }
    
    /* We want our own pool with own allocator to keep data across watchdog invocations.
     * Since we'll run in a single watchdog thread, using our own allocator will prevent 
     * any confusion in the parent pool. */
    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, 1);
    rv = apr_pool_create_ex(&octxp, p, NULL, allocator);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10062) "md_ocsp_watchdog: create pool");
        return rv;
    }
    apr_allocator_owner_set(allocator, octxp);
    apr_pool_tag(octxp, "md_ocsp_watchdog");

    octx = apr_pcalloc(octxp, sizeof(*octx));
    octx->p = octxp;
    octx->s = s;
    octx->mc = mc;
    /* renew on 30% remaining /*/
    md_timeslice_create(&octx->renew_window, octx->p, 
                        apr_time_from_sec(100 * 3600), apr_time_from_sec(30 * 3600)); 
    
    /* TODO: make sure that store is prepped, has correct permissions and
     * perform house-keeping, such as removing OCSP responses no longer used
     * and older than 24 hours. */
    
    rv = wd_get_instance(&octx->watchdog, MD_OCSP_WATCHDOG_NAME, 0, 1, octx->p);
    if (APR_SUCCESS != rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO() 
                     "create md ocsp watchdog(%s)", MD_OCSP_WATCHDOG_NAME);
        return rv;
    }
    rv = wd_register_callback(octx->watchdog, 0, octx, run_watchdog);
    ap_log_error(APLOG_MARK, rv? APLOG_CRIT : APLOG_DEBUG, rv, s, APLOGNO() 
                 "register md ocsp watchdog(%s)", MD_OCSP_WATCHDOG_NAME);
    return rv;
}



