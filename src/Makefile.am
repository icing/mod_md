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

lib_LTLIBRARIES    = libmd.la mod_md.la

#---------------------------------------------------------------------------------------------------
# static lib, linked by module and a2md
#---------------------------------------------------------------------------------------------------

libmd_la_CPPFLAGS = -fPIC -g -std=c99 -D_GNU_SOURCE -Werror @WERROR_CFLAGS@
libmd_la_LDFLAGS  = @LDFLAGS@ -static -ljansson -lcurl -lssl -lcrypto

A2LIB_OBJECTS = \
    md_acme.c \
    md_acme_acct.c \
    md_acme_authz.c \
    md_acme_drive.c \
    md_acme_order.c \
    md_acmev1_drive.c \
    md_acmev2_drive.c \
    md_core.c \
    md_curl.c \
    md_crypt.c \
    md_http.c \
    md_json.c \
    md_jws.c \
    md_log.c \
    md_reg.c \
    md_store.c \
    md_store_fs.c \
    md_util.c

A2LIB_HFILES = \
    md_acme.h \
    md_acme_acct.h \
    md_acme_authz.h \
    md_acme_drive.h \
    md_acme_order.h \
    md_acmev1_drive.h \
    md_acmev2_drive.h \
    md_curl.h \
    md_crypt.h \
    md_http.h \
    md_json.h \
    md_jws.h \
    md_log.h \
    md_reg.h \
    md_store.h \
    md_store_fs.h \
    md_util.h \
    md.h
    
    
libmd_la_SOURCES = $(A2LIB_HFILES) $(A2LIB_OBJECTS)

#---------------------------------------------------------------------------------------------------
# mod_md for httpd
#---------------------------------------------------------------------------------------------------

mod_md_la_CPPFLAGS = -g -I../src -std=c99 -D_GNU_SOURCE -Werror @WERROR_CFLAGS@
mod_md_la_LDFLAGS  = -module -L../src -lmd -ljansson -lcurl -lssl -lcrypto -export-symbols-regex md_module


OBJECTS = \
    mod_md_config.c \
    mod_md_drive.c \
    mod_md_os.c \
    mod_md_status.c \
    mod_md.c

HFILES = \
    mod_md_config.h \
    mod_md_drive.h \
    mod_md_os.h \
    mod_md_status.h \
    mod_md_private.h \
    mod_md.h

mod_md_la_SOURCES = $(HFILES) $(OBJECTS) libmd.la

EXTRA_mod_md_la_DEPENDENCIES = libmd.la

all: mod_md.la 

#---------------------------------------------------------------------------------------------------
# a2md executable
#---------------------------------------------------------------------------------------------------

bin_PROGRAMS       = a2md

a2md_CFLAGS  = -g -I../src -std=c99 -D_GNU_SOURCE -Werror @WERROR_CFLAGS@
a2md_LDFLAGS = @LDFLAGS@ -L../src -lmd -l@LIB_APR@ -l@LIB_APRUTIL@ -ljansson -lcurl -lssl -lcrypto

A2MD_OBJECTS = \
    md_cmd_main.c \
    md_cmd_acme.c \
    md_cmd_reg.c \
    md_cmd_store.c

A2MD_HFILES = \
    md_cmd.h \
    md_cmd_acme.h \
    md_cmd_reg.h \
    md_cmd_store.h

a2md_SOURCES = $(A2MD_HFILES) $(A2MD_OBJECTS)

EXTRA_a2md_DEPENDENCIES = libmd.la

#---------------------------------------------------------------------------------------------------
# installations
#---------------------------------------------------------------------------------------------------

install-libLTLIBRARIES: libmd.la
	@echo "not installing libmd.a or module"

install-exec-local: mod_md.la
	$(MKDIR_P) $(DESTDIR)/@LIBEXEC_DIR@
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)/@LIBEXEC_DIR@ -n md mod_md.la
