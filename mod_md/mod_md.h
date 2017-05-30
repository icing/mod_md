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

#ifndef mod_md_mod_md_h
#define mod_md_mod_md_h

struct apr_array_header_t;


#define MD_INCOMPLETE     0x0
#define MD_LIVE           0x1
#define MD_EXPIRED        0x2

/**
 * Get the status of the Managed Domain that contains the given DNS name.
 *
 * @param domain the DNS name to get the status for
 * @param pstate receives the status of the Managed Domain on success 
 * @return APR_ENOENT if domain is not known.
 */
apr_status_t md_get_status(const char *domain, int *pstate);

/**
 * Get the certificate files and keys for the domain. Only valid for Managed Domains in
 * state LIVE or EXPIRED. Certificate files and key files will be handed out in matching order.
 * The certificate files will first contain the domain certificate, followed by the
 * certificate chain files. A file may contain all together. Key files may be empty. 
 *
 * @param domain the DNS name to get the certificates for
 * @param certs  the list to be filled with the certificate file paths
 * @param keys   the list to be filled with the private key file paths
 */
apr_status_t md_get_cert_files(const char *domain, 
                               struct apr_array_header_t *certs, 
                               struct apr_array_header_t *keys);

#endif /* mod_md_mod_md_h */
