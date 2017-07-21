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


bin_PROGRAMS       = a2md

a2md_CFLAGS  = -g -I../src -std=c99 -D_GNU_SOURCE -Werror
a2md_LDFLAGS = @LDFLAGS@ -static -L../src -lapachemd -shared -l@LIB_APR@ -l@LIB_APRUTIL@ -ljansson -lcurl -lssl -lcrypto

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
