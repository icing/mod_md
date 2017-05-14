# Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS = foreign

CFLAGS  = -g -I ../mod_md
LDFLAGS = -lapr-1 -laprutil-1  -lcurl -lssl -lcrypto

bin_PROGRAMS = a2md

a2md_SOURCES = \
    md_main.c \
    ../mod_md/md_acme.c \
    ../mod_md/md_acme_acct.c \
    ../mod_md/md_crypt.c \
    ../mod_md/md_http.c \
    ../mod_md/md_json.c \
    ../mod_md/md_jws.c \
    ../mod_md/md_util.c


