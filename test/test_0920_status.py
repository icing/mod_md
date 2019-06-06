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
from httplib import HTTPSConnection
from test_base import TestEnv
from test_base import HttpdConf
from test_base import CertUtil
from shutil import copyfile


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.APACHE_CONF_SRC = "data/test_auto"
    TestEnv.check_acme()
    TestEnv.clear_store()
    TestEnv.install_test_conf();
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0

class TestStatus:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.apache_err_reset();
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_920_001(self):
        # simple MD, drive it, check status before activation
        domain = self.test_domain
        dnsList = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        # we started without a valid certificate, so we expect /.httpd/certificate-status
        # to not give information about one and - since we waited for the ACME signup
        # to complete - to give information in 'renewal' about the new cert.
        status = TestEnv.get_certificate_status( domain )
        assert not 'sha256-fingerprint' in status
        assert not 'valid-until' in status
        assert not 'valid-from' in status
        assert 'renewal' in status
        assert 'valid-until' in status['renewal']
        assert 'valid-from' in status['renewal']
        assert 'sha256-fingerprint' in status['renewal']
        # restart and activate
        # once activated, the staging must be gone and attributes exist for the active cert
        assert TestEnv.apache_restart() == 0
        status = TestEnv.get_certificate_status( domain )
        assert not 'renewal' in status
        assert 'sha256-fingerprint' in status
        assert 'valid-until' in status
        assert 'valid-from' in status

    def test_920_002(self):
        # simple MD, drive it, manipulate staged credentials and check status
        domain = self.test_domain
        dnsList = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        # copy a real certificate from LE over to staging
        staged_cert = os.path.join(TestEnv.STORE_DIR, 'staging', domain, 'pubcert.pem') 
        real_cert = os.path.join('data', 'test_920', '002.pubcert')
        assert copyfile(real_cert, staged_cert) == None
        status = TestEnv.get_certificate_status( domain )
        # status shows the copied cert's properties as staged
        assert 'renewal' in status
        assert 'Thu, 29 Aug 2019 16:06:35 GMT' == status['renewal']['valid-until']
        assert 'Fri, 31 May 2019 16:06:35 GMT' == status['renewal']['valid-from']
        assert '03039C464D454EDE79FCD2CAE859F668F269' ==  status['renewal']['serial'] 
        assert 'sha256-fingerprint' in status['renewal']
        assert len(status['renewal']['scts']) == 2
        assert status['renewal']['scts'][0]['logid'] == '747eda8331ad331091219cce254f4270c2bffd5e422008c6373579e6107bcc56'
        assert status['renewal']['scts'][0]['signed'] == 'Fri, 31 May 2019 17:06:35 GMT'
        assert status['renewal']['scts'][1]['logid'] == '293c519654c83965baaa50fc5807d4b76fbf587a2972dca4c30cf4e54547f478'
        assert status['renewal']['scts'][1]['signed'] == 'Fri, 31 May 2019 17:06:35 GMT'
