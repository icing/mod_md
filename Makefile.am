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
DIST_SUBDIRS    = src mod_md

ACLOCAL_AMFLAGS = -I m4


dist_doc_DATA   = README README.md LICENSE

.PHONY: test

mod_md: src

SERVER_DIR      = @SERVER_DIR@

test: $(SERVER_DIR)/.test-setup src/a2md
	@cd test; py.test

test-drive: $(SERVER_DIR)/.test-setup src/a2md
	@cd test; py.test test_0500_drive.py

test-configs: $(SERVER_DIR)/.test-setup src/a2md
	@cd test; py.test test_1000_conf_validate.py test_1100_conf_store.py

$(SERVER_DIR)/.test-setup: test/conf/* \
		$(SERVER_DIR)/conf/ssl/cert.pem
	@mkdir -p $(SERVER_DIR)/conf
	@mkdir -p $(SERVER_DIR)/htdocs
	@mkdir -p $(SERVER_DIR)/logs
	@cp test/conf/*.* $(SERVER_DIR)/conf
	@touch $(SERVER_DIR)/.test-setup

$(SERVER_DIR)/conf/ssl/cert.key:
	@mkdir -p $(SERVER_DIR)/conf/ssl
	openssl genrsa -out $(SERVER_DIR)/conf/ssl/cert.key 4096

$(SERVER_DIR)/conf/ssl/cert.req: \
		$(SERVER_DIR)/conf/ssl/cert.key \
        test/conf/ssl/cert-template.conf
	openssl req -new -key $(SERVER_DIR)/conf/ssl/cert.key \
		-out $(SERVER_DIR)/conf/ssl/cert.req \
	    -config test/conf/ssl/cert-template.conf

$(SERVER_DIR)/conf/ssl/cert.pem: \
	$(SERVER_DIR)/conf/ssl/cert.key \
	$(SERVER_DIR)/conf/ssl/cert.req \
	test/conf/ssl/extensions.conf
	openssl x509 -req -sha256 -days 1095 \
		-signkey $(SERVER_DIR)/conf/ssl/cert.key \
		-in $(SERVER_DIR)/conf/ssl/cert.req \
		-out $(SERVER_DIR)/conf/ssl/cert.pem \
        -extfile test/conf/ssl/extensions.conf -extensions ssl_test
