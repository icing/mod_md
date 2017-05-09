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
#include "md_private.h"


static int ap_array_str_case_index(const apr_array_header_t *array, 
                                   const char *s, int start)
{
    if (start >= 0) {
        int i;
        
        for (i = start; i < array->nelts; i++) {
            const char *p = APR_ARRAY_IDX(array, i, const char *);
            if (!apr_strnatcasecmp(p, s)) {
                return i;
            }
        }
    }
    
    return -1;
}

int md_contains(const md_t *md, const char *domain)
{
   return ap_array_str_case_index(md->domains, domain, 0) >= 0;
}

const char *md_common_name(const md_t *md1, const md_t *md2)
{
    int i;
    
    if (md1 == NULL || md1->domains == NULL
        || md2 == NULL || md2->domains == NULL) {
        return NULL;
    }
    
    for (i = 0; i < md1->domains->nelts; ++i) {
        const char *name1 = APR_ARRAY_IDX(md1->domains, i, const char*);
        if (md_contains(md2, name1)) {
            return name1;
        }
    }
    return NULL;
}

int md_names_overlap(const md_t *md1, const md_t *md2)
{
    return md_common_name(md1, md2) != NULL;
}

const char *md_create(md_t **pmd, apr_pool_t *p, int argc, char *const argv[])
{
    md_t *md;
    const char *name;
    const char **np;
    int i;
    
    if (!argc) {
        return "needs at least one name";
    }

    md = apr_pcalloc(p, sizeof(*md));
    md->domains = apr_array_make(p, argc, sizeof(const char *));
    
    for (i = 0; i < argc; ++i) {
        name = argv[i];
        /* TODO: some dns sanity check on the name? */
        if (ap_array_str_case_index(md->domains, name, 0) < 0) {
            np = (const char **)apr_array_push(md->domains);
            *np = name;
        }
        if (!md->name) {
            md->name = name;
        }
    }
 
    *pmd = md;
    return NULL;   
}

md_t *md_clone(apr_pool_t *p, md_t *src)
{
    md_t *md;
    
    md = apr_pcalloc(p, sizeof(*md));
    md->name = apr_pstrdup(p, src->name);
    md->domains = apr_array_copy(p, src->domains);
    return md;   
}
