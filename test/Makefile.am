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

data/ssl/valid_pkey.pem:
	@mkdir -p data/ssl
	openssl genrsa -out data/ssl/valid_pkey.pem 4096

data/ssl/valid_cert.req: \
		data/ssl/valid_pkey.pem \
		data/ssl/req-template.conf
	openssl req -new -key data/ssl/valid_pkey.pem \
		-out data/ssl/valid_cert.req \
		-config data/ssl/req-template.conf

data/ssl/valid_cert.pem: \
		data/ssl/valid_pkey.pem \
		data/ssl/valid_cert.req
	openssl x509 -req -sha256 -days 1095 \
		-signkey data/ssl/valid_pkey.pem \
		-in data/ssl/valid_cert.req \
		-out data/ssl/valid_cert.pem

clean-local:
        -rm -f data/ssl/valid_*
