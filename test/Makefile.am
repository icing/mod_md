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

SERVER_DIR     = @SERVER_DIR@
GEN            = gen
ACME_TEST_URL  = @ACME_TEST_URL@
ACME_TEST_DIR  = @ACME_TEST_DIR@


.phony: unit_tests

EXTRA_DIST     = modules pyhttpd unit
 	
dist-hook:
	rm -rf $(distdir)/pyhttpd/htdocs/test1/apache.org-files


if BUILD_UNIT_TESTS
TESTS = unit/main

check_PROGRAMS = unit/main

unit_main_SOURCES = unit/main.c unit/test_md_json.c unit/test_md_util.c unit/test_common.h
unit_main_LDADD   = $(top_builddir)/src/libmd.la

unit_main_CFLAGS  = $(CHECK_CFLAGS) -I$(top_srcdir)/src
unit_main_LDADD  += $(CHECK_LIBS) -l$(LIB_APR) -l$(LIB_APRUTIL)

unit_tests: $(TESTS)
	@echo "============================= unit tests (check) ==============================="
	@$(TESTS)
else

unit_tests: $(TESTS)
	@echo "unit tests disabled"
        
endif

test: unit_tests
	pytest

clean-local:
	rm -f $(SERVER_DIR)/conf/ssl/*
	rm -rf *.pyc __pycache__
	rm -f data/ssl/valid*
	rm -rf $(SERVER_DIR)
