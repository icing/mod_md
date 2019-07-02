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

#ifndef mod_md_md_ocsp_h
#define mod_md_md_ocsp_h


apr_status_t md_ocsp_init_stapling_status(server_rec *s, apr_pool_t *p, 
                                          void *x509cert, void *x509issuer);

apr_status_t md_ocsp_get_stapling_status(unsigned char **pder, int *pderlen, 
                                         conn_rec *c, server_rec *s, void *x509cert);
                          

#endif /* mod_md_md_ocsp_h */
