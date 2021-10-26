# Copyright 2019 greenbytes GmbH (https://www.greenbytes.de)
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
DIST_SUBDIRS    = src test

ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA   = README README.md LICENSE
EXTRA_DIST      = patches a2md.xml

if BUILD_MANPAGES
man1_MANS = a2md.1

a2md.1: $(srcdir)/a2md.xml
	rm -f a2md.1
	$(XMLTO) --skip-validation man $(srcdir)/a2md.xml

endif

.PHONY: test

test: all-recursive
	$(MAKE) -C test/ test

docker-test:
	docker-compose build debian-sid
	docker-compose run debian-sid
