# Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
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
SUBDIRS         = @BUILD_SUBDIRS@
DIST_SUBDIRS    = src mod_md a2md

ACLOCAL_AMFLAGS = -I m4


dist_doc_DATA   = README README.md LICENSE

.PHONY: test libmd

libmd:
	$(MAKE) -C src

a2md/a2md: libmd
	$(MAKE) -C a2md

mod_md/mod_md.la: libmd
	$(MAKE) -C mod_md

mod_md: libmd

test: a2md/a2md mod_md/mod_md.la
	$(MAKE) -C test/ test

test-auto: a2md/a2md mod_md/mod_md.la
	$(MAKE) -C test/ test-auto

test-drive: a2md/a2md mod_md/mod_md.la
	$(MAKE) -C test/ test-drive

test-configs: a2md/a2md mod_md/mod_md.la
	$(MAKE) -C test/ test-configs

