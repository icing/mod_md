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
SUBDIRS =

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES    = mod_md.la

mod_md_la_CPPFLAGS = -std=c99 -D_GNU_SOURCE -Werror
mod_md_la_LDFLAGS  = -module

OBJECTS = \
    acme/md_acme.c \
    acme/md_acme_acct.c \
    acme/md_acme_authz.c \
    acme/md_acme_cert.c \
    md_config.c \
    md_core.c \
    md_crypt.c \
    md_http.c \
    md_json.c \
    md_jws.c \
    md_log.c \
    md_reg.c \
    md_store.c \
    md_util.c \
    mod_md.c

HFILES = \
    acme/md_acme.h \
    acme/md_acme_acct.h \
    acme/md_acme_authz.h \
    acme/md_acme_cert.h \
    md_config.h \
    md_crypt.h \
    md_http.h \
    md_json.h \
    md_jws.h \
    md_log.h \
    md_reg.h \
    md_store.h \
    md_util.h \
    md.h \
    mod_md.h

mod_md_la_SOURCES = $(HFILES) $(OBJECTS)

all: mod_md.la 

install-libLTLIBRARIES:
	@: # override

install-exec-local: mod_md.la
	$(MKDIR_P) $(DESTDIR)/@LIBEXEC_DIR@
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)/@LIBEXEC_DIR@ -n h2 mod_md.la


