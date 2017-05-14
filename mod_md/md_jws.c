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

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_buckets.h>

#include "md_crypt.h"
#include "md_json.h"
#include "md_jws.h"
#include "md_util.h"

apr_status_t md_jws_sign(md_json **pmsg, apr_pool_t *p,
                         const char *payload, size_t len, 
                         struct apr_table_t *protected, 
                         struct md_pkey *pkey, const char *key_id)
{
    md_json *msg, *prot_msg;
    apr_status_t status;
    const char *prot64, *pay64, *sign64, *s;
    
    status = md_json_create(&msg, p);
    if (status != APR_SUCCESS) {
        return status;
    }
    
    pay64 = md_util_base64url_encode(payload, len, p);
    if (!pay64) {
        return APR_ENOMEM;
    }
    
    status = md_json_create(&prot_msg, p);
    if (status != APR_SUCCESS) {
        return status;
    }

    md_json_setsv(prot_msg, "alg", "RS256", NULL);
    if (key_id) {
        md_json_setsv(prot_msg, "kid", key_id, NULL);
    }
    else {
        md_json_setsv(prot_msg, "jwk", "e", md_crypt_pkey_get_rsa_e64(pkey, p), NULL);
        md_json_setsv(prot_msg, "jwk", "kty", "RSA", NULL);
        md_json_setsv(prot_msg, "jwk", "n", md_crypt_pkey_get_rsa_n64(pkey, p), NULL);
    }

    
    s = md_json_writep(prot_msg, MD_JSON_FMT_COMPACT, p);
    fprintf(stderr, "prot_msg: %s\n", s);
    prot64 = s? md_util_base64url_encode(s, strlen(s), p) : NULL;
    if (!prot64) {
        return APR_ENOMEM;
    }
    md_json_setsv(msg, "protected", prot64, NULL);
    
    (void)sign64;
    *pmsg = msg;
    return status;
}
