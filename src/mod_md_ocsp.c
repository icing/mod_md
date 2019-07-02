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

#include "md.h"
#include "md_crypt.h"
#include "md_http.h"
#include "md_json.h"
#include "md_ocsp.h"
#include "md_store.h"
#include "md_log.h"
#include "md_reg.h"
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
    
    sc = md_config_get(s);
    if (!staple_here(sc)) goto declined;

    md = sc->assigned;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, "get stapling for: %s", 
                  md? md->name : s->server_hostname);
    return md_ocsp_get_status(pder, pderlen, sc->mc->ocsp, 
                              md_cert_wrap(c->pool, x509cert), c->pool, md);
    
declined:
    return DECLINED;
}
                          
