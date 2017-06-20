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


lib_LTLIBRARIES    = libapachemd.la
bin_PROGRAMS       = a2md

libapachemd_la_CPPFLAGS = -g -std=c99 -D_GNU_SOURCE -Werror
libapachemd_la_LDFLAGS  = @LDFLAGS@ -lapr-1 -laprutil-1  -lcurl -lssl -lcrypto

A2LIB_OBJECTS = \
    acme/md_acme.c \
    acme/md_acme_acct.c \
    acme/md_acme_authz.c \
    acme/md_acme_drive.c \
    md_core.c \
    md_crypt.c \
    md_http.c \
    md_json.c \
    md_jws.c \
    md_log.c \
    md_reg.c \
    md_store.c \
    md_util.c

A2LIB_HFILES = \
    acme/md_acme.h \
    acme/md_acme_acct.h \
    acme/md_acme_authz.h \
    acme/md_acme_drive.h \
    md_crypt.h \
    md_http.h \
    md_json.h \
    md_jws.h \
    md_log.h \
    md_reg.h \
    md_store.h \
    md_util.h \
    md.h
    
    
libapachemd_la_SOURCES = $(A2LIB_HFILES) $(A2LIB_OBJECTS)

a2md_CFLAGS  = -g
a2md_LDFLAGS = @LDFLAGS@ -lapachemd

A2MD_OBJECTS = \
    md_main.c \
    md_cmd_acme.c \
    md_cmd_reg.c \
    md_cmd_store.c

A2MD_HFILES = \
    md_cmd.h \
    md_cmd_acme.h \
    md_cmd_reg.h \
    md_cmd_store.h

a2md_SOURCES = $(A2MD_HFILES) $(A2MD_OBJECTS)
