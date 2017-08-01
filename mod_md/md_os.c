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
#include <apr_strings.h>

#include <mpm_common.h>
#include <httpd.h>
#include <http_log.h>
#include <ap_mpm.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef WIN32
#include "mpm_winnt.h"
#endif
#if AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "md_util.h"
#include "md_os.h"

#if 0

#define MD_ERRFN_USERDATA_KEY         "MDCHILDERRFN"

static void grace_child_errfn(apr_pool_t *pool, apr_status_t err, const char *description)
{
    server_rec *s;
    void *v;

    apr_pool_userdata_get(&v, MD_ERRFN_USERDATA_KEY, pool);
    s = v;

    if (s) {
        ap_log_error(APLOG_MARK, APLOG_ERR, err, s, APLOGNO() "%s", description);
    }
}

static apr_status_t server_graceful(apr_proc_t **pproc, apr_pool_t *p, server_rec *s) 
{
    apr_procattr_t *attr;
    apr_status_t rv;
    const char **argv;
    apr_proc_t *proc;
    
    if (APR_SUCCESS != (rv = apr_procattr_create(&attr, p))
        || APR_SUCCESS != (rv = apr_procattr_io_set(attr, APR_NO_PIPE, APR_NO_PIPE, APR_NO_PIPE))
        || APR_SUCCESS != (rv = apr_procattr_cmdtype_set(attr, APR_PROGRAM_PATH))
        || APR_SUCCESS != (rv = apr_procattr_detach_set(attr, 1))
        || APR_SUCCESS != (rv = apr_procattr_child_errfn_set(attr, grace_child_errfn))) {
        return rv;
    }
    apr_pool_userdata_set(s, MD_ERRFN_USERDATA_KEY, apr_pool_cleanup_null, p);
    
    proc = apr_pcalloc(p, sizeof(*proc));
    proc->pid = -1;
    proc->err = proc->in = proc->out = NULL;

    argv = (const char **)apr_pcalloc(p, 6 * sizeof(const char *));
    argv[0] = "/opt/apache-trunk/bin/apachectl";
    argv[1] = "-d";
    argv[2] = ap_server_root_relative(p, "");
    argv[3] = "-k";
    argv[4] = "graceful";
    argv[5] = NULL;
    
    ap_log_error( APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO() "%s started (%s)", argv[0], argv[2]);
    /*rv = apr_proc_create(proc, argv[0], argv, NULL, attr, p); 
    ap_log_error( APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO() "graceful restart");
    *pproc = proc;
    
    return rv;*/
    return APR_ENOTIMPL;
}
#endif /* 0 */

apr_status_t md_try_chown(const char *fname, int uid, int gid, apr_pool_t *p)
{
#if AP_NEED_SET_MUTEX_PERMS
    if (-1 == chown(fname, (uid_t)uid, (gid_t)gid)) {
        apr_status_t rv = APR_FROM_OS_ERROR(errno);
        if (!APR_STATUS_IS_ENOENT(rv)) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, rv, p, APLOGNO()
                         "Can't change owner of %s", fname);
        }
        return rv;
    }
    return APR_SUCCESS;
#else 
    return APR_ENOTIMPL;
#endif
}

apr_status_t md_make_worker_accessible(const char *fname, apr_pool_t *p)
{
#if AP_NEED_SET_MUTEX_PERMS
    return md_try_chown(fname, ap_unixd_config.user_id, -1, p);
#else 
    return APR_ENOTIMPL;
#endif
}

#ifdef WIN32

/* TOOD: test if this has a chance to work on WIN32 systems */
static apr_status_t mpm_signal_service(apr_pool_t *ptemp, int signal)
{
    return APR_ENOTIMPL;
}

apr_status_t md_server_graceful(apr_pool_t *p, server_rec *s)
{
    return mpm_signal_service(p, 1);
}
 
#else

apr_status_t md_server_graceful(apr_pool_t *p, server_rec *s)
{ 
    if (kill(getppid(), AP_SIG_GRACEFUL) < 0) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, errno, NULL, "sending signal to parent");
        return APR_EACCES;
    }
    return APR_SUCCESS;
}

#endif

