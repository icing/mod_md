# test mod_md status resources

import json
import os
import pytest
import re
import socket
import ssl
import sys
import time

from datetime import datetime
from TestEnv import TestEnv
from TestHttpdConf import HttpdConf
from TestCertUtil import CertUtil
from shutil import copyfile


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.APACHE_CONF_SRC = "data/test_auto"
    TestEnv.check_acme()
    TestEnv.clear_store()
    HttpdConf().install();
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0

class TestStatus:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # simple MD, drive it, check status before activation
    def test_920_001(self):
        domain = self.test_domain
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( domains )
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        # we started without a valid certificate, so we expect /.httpd/certificate-status
        # to not give information about one and - since we waited for the ACME signup
        # to complete - to give information in 'renewal' about the new cert.
        status = TestEnv.get_certificate_status( domain )
        assert not 'sha256-fingerprint' in status
        assert not 'valid' in status
        assert 'renewal' in status
        assert 'valid' in status['renewal']
        assert 'sha256-fingerprint' in status['renewal']
        # restart and activate
        # once activated, the staging must be gone and attributes exist for the active cert
        assert TestEnv.apache_restart() == 0
        status = TestEnv.get_certificate_status( domain )
        assert not 'renewal' in status
        assert 'sha256-fingerprint' in status
        assert 'valid' in status
        assert 'from' in status['valid']

    # simple MD, drive it, manipulate staged credentials and check status
    def test_920_002(self):
        domain = self.test_domain
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( domains )
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        # copy a real certificate from LE over to staging
        staged_cert = os.path.join(TestEnv.STORE_DIR, 'staging', domain, 'pubcert.pem') 
        real_cert = os.path.join('data', 'test_920', '002.pubcert')
        assert copyfile(real_cert, staged_cert)
        status = TestEnv.get_certificate_status( domain )
        # status shows the copied cert's properties as staged
        assert 'renewal' in status
        assert 'Thu, 29 Aug 2019 16:06:35 GMT' == status['renewal']['valid']['until']
        assert 'Fri, 31 May 2019 16:06:35 GMT' == status['renewal']['valid']['from']
        assert '03039C464D454EDE79FCD2CAE859F668F269' ==  status['renewal']['serial'] 
        assert 'sha256-fingerprint' in status['renewal']
        if 0 == 1:
            assert len(status['renewal']['scts']) == 2
            assert status['renewal']['scts'][0]['logid'] == '747eda8331ad331091219cce254f4270c2bffd5e422008c6373579e6107bcc56'
            assert status['renewal']['scts'][0]['signed'] == 'Fri, 31 May 2019 17:06:35 GMT'
            assert status['renewal']['scts'][1]['logid'] == '293c519654c83965baaa50fc5807d4b76fbf587a2972dca4c30cf4e54547f478'
            assert status['renewal']['scts'][1]['signed'] == 'Fri, 31 May 2019 17:06:35 GMT'

    # test if switching status off has effect
    def test_920_003(self):
        domain = self.test_domain
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( domains )
        conf.add_line("MDCertificateStatus off")
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        status = TestEnv.get_certificate_status( domain )
        assert not status

    # get the complete md-status JSON, check that it
    def test_920_004(self):
        domain = self.test_domain
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( domains )
        conf.add_line("MDCertificateStatus off")
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        status = TestEnv.get_md_status( "" )
        assert "version" in status
        assert "managed-domains" in status
        assert 1 == len(status["managed-domains"])

    # get the status of a domain on base server
    def test_920_010(self):
        domain = self.test_domain
        domains = [ domain ]
        conf = HttpdConf(std_vhosts=False, text="""
LogLevel md:trace2
LogLevel ssl:debug
                
MDBaseServer on
MDPortMap http:- https:%s

Listen %s
ServerAdmin admin@not-forbidden.org
ServerName %s
SSLEngine on
Protocols h2 http/1.1 acme-tls/1

<Location "/server-status">
    SetHandler server-status
</Location>
<Location "/md-status">
    SetHandler md-status
</Location>
            """ % (TestEnv.HTTPS_PORT, TestEnv.HTTPS_PORT, domain))
        conf.add_md( domains )
        conf.install()
        TestEnv.HTTPD_CHECK_URL = TestEnv.HTTPD_URL_SSL
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        status = TestEnv.get_md_status( "" )
        assert "version" in status
        assert "managed-domains" in status
        assert 1 == len(status["managed-domains"])
        # get the html page
        status = TestEnv.get_server_status()
        assert re.search(r'<h3>Managed Certificates</h3>', status, re.MULTILINE)
        # get the ascii summary
        status = TestEnv.get_server_status(query="?auto")
        m = re.search(r'Managed Certificates: total=(\d+), ok=(\d+) renew=(\d+) errored=(\d+) ready=(\d+)', status, re.MULTILINE)
        assert 1 == int(m.group(1))
        assert 0 == int(m.group(2))
        assert 1 == int(m.group(3))
        assert 0 == int(m.group(4))
        assert 1 == int(m.group(5))
