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

SERVER_DIR     = @SERVER_DIR@
GEN            = gen

all: $(SERVER_DIR)/.test-setup

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

test: $(SERVER_DIR)/.test-setup
	py.test

test-drive: $(SERVER_DIR)/.test-setup
	@py.test test_0500_drive.py
	@py.test test_0600_roundtrip.py
	@py.test test_0700_auto.py

test-auto: $(SERVER_DIR)/.test-setup
	@py.test test_0700_auto.py

test-configs: $(SERVER_DIR)/.test-setup
	@py.test test_0300_conf_validate.py
	@py.test test_0310_conf_store.py

$(SERVER_DIR)/.test-setup: conf/* \
		$(SERVER_DIR)/htdocs/index.html \
		$(SERVER_DIR)/conf/ssl/valid_cert.pem \
		$(SERVER_DIR)/conf/ssl/expired_cert.pem \
		$(SERVER_DIR)/conf/ssl/expired_pkey.pem
	@mkdir -p $(SERVER_DIR)/conf/ssl
	@mkdir -p $(SERVER_DIR)/logs
	rsync -a --exclude="httpd*" conf/*.* $(SERVER_DIR)/conf
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
