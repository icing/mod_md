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
BOULDER_DIR    = @BOULDER_DIR@

.phony: unit_tests

EXTRA_DIST     = conf data htdocs
 	
dist-hook:
	rm -rf $(distdir)/conf/httpd.conf
	rm -rf $(distdir)/conf/proxy.conf
	rm -rf $(distdir)/conf/modules.conf
	rm -rf $(distdir)/conf/modules.conf
	rm -rf $(distdir)/conf/std_vhosts.conf
	cp -p $(srcdir)/*.py $(distdir)



if BUILD_UNIT_TESTS
TESTS = unit/main

check_PROGRAMS = unit/main

unit_main_SOURCES = unit/main.c unit/test_md_json.c unit/test_md_util.c unit/test_common.h
unit_main_LDADD   = $(top_builddir)/src/libmd.la

unit_main_CFLAGS  = $(CHECK_CFLAGS) -Werror -I$(top_srcdir)/src
unit_main_LDADD  += $(CHECK_LIBS) -l$(LIB_APR) -l$(LIB_APRUTIL)

unit_tests: $(TESTS)
	@echo "============================= unit tests (check) ==============================="
	@$(TESTS)
else

unit_tests: $(TESTS)
	@echo "unit tests disabled"
        
endif


$(SERVER_DIR)/conf/ssl/valid_pkey.pem:
	@mkdir -p $(SERVER_DIR)/conf/ssl
	openssl genrsa -out $(SERVER_DIR)/conf/ssl/valid_pkey.pem 4096

$(SERVER_DIR)/conf/ssl/valid_cert.req: \
		$(SERVER_DIR)/conf/ssl/valid_pkey.pem \
		data/ssl/req_template.conf
	openssl req -new -key $(SERVER_DIR)/conf/ssl/valid_pkey.pem \
		-out $(SERVER_DIR)/conf/ssl/valid_cert.req \
		-config data/ssl/req_template.conf

$(SERVER_DIR)/conf/ssl/valid_cert.pem: \
		$(SERVER_DIR)/conf/ssl/valid_pkey.pem \
		$(SERVER_DIR)/conf/ssl/valid_cert.req
	openssl x509 -req -sha256 -days 1095 \
		-signkey $(SERVER_DIR)/conf/ssl/valid_pkey.pem \
		-in $(SERVER_DIR)/conf/ssl/valid_cert.req \
		-out $(SERVER_DIR)/conf/ssl/valid_cert.pem \
		-extfile data/ssl/req_exts.conf -extensions v3_req_ext

test: $(SERVER_DIR)/.test-setup unit_tests
	python3 -m pytest

# The certificates we need to verify the cert chain we retrieved from ACME
# For now, we need these two, although a fix is underway that only one becomes
# necessary. See: https://github.com/letsencrypt/boulder/issues/3307
@BOULDER_DIR@:
	@test -d $(BOULDER_DIR) || echo "boulder installation not found. Please configure using --with-boulder-dir to specify the correct location."; exit 1

# we used to get the test root cert this way, but boulder keeps changing it
#@cat $(BOULDER_DIR)/test/test-root.pem > $(GEN)/ca.pem
# this is the current way, boulder docker needs to be running    
$(GEN)/ca.pem: \
    $(BOULDER_DIR) \
    $(BOULDER_DIR)/test/test-root.pem
	@echo "copying issuer certitificates from boulder docker image"    
	@docker exec boulder_boulder_1 bash -c "cat /tmp/root*.pem" >$@

$(SERVER_DIR)/.test-setup: conf/* \
		$(SERVER_DIR)/htdocs/index.html \
		$(SERVER_DIR)/conf/ssl/valid_cert.pem \
		$(SERVER_DIR)/conf/ssl/expired_cert.pem \
		$(SERVER_DIR)/conf/ssl/expired_pkey.pem \
                $(wildcard conf/*.conf) \
                $(GEN)/ca.pem      
	@mkdir -p $(SERVER_DIR)/conf/ssl
	@mkdir -p $(SERVER_DIR)/logs
	rsync -a --exclude="*.in" conf/*.* $(SERVER_DIR)/conf
	@touch $(SERVER_DIR)/.test-setup

$(SERVER_DIR)/conf/ssl/expired_cert.pem: data/ssl/expired_cert.pem
	@cp $<  $@

$(SERVER_DIR)/conf/ssl/expired_pkey.pem: data/ssl/expired_pkey.pem
	@cp $<  $@

$(SERVER_DIR)/htdocs/index.html: htdocs/index.html
	@mkdir -p $(SERVER_DIR)/htdocs
	@cp htdocs/*.* $(SERVER_DIR)/htdocs 

clean-local:
	rm -f $(SERVER_DIR)/conf/ssl/*
	rm -rf *.pyc __pycache__
	rm -f data/ssl/valid*
	rm -rf $(SERVER_DIR)
