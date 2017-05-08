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

#ifndef mod_md_md_config_h
#define mod_md_md_config_h

typedef enum {
    MD_CONFIG_CA_URL,
    MD_CONFIG_CA_PROTO,
} md_config_var_t;

typedef struct md_config {
    const char *name;
    
    apr_array_header_t *mds; /* array of md_t pointers */
    const char *ca_url;
    const char *ca_proto;
} md_config;

void *md_config_create_svr(apr_pool_t *pool, server_rec *s);
void *md_config_merge_svr(apr_pool_t *pool, void *basev, void *addv);

extern const command_rec md_cmds[];

const md_config *md_config_get(conn_rec *c);
const md_config *md_config_sget(server_rec *s);

const char *md_config_var_get(const md_config *config, md_config_var_t var);

#endif /* md_config_h */
