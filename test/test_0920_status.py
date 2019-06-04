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
    assert TestEnv.apache_start() == 0
    

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestAuto:

    @classmethod
    def setup_class(cls):
        time.sleep(1)
        cls.dns_uniq = "%d.org" % time.time()
        cls.TMP_CONF = os.path.join(TestEnv.GEN_DIR, "auto.conf")


    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.apache_err_reset();
        TestEnv.clear_store()
        TestEnv.install_test_conf();
        self.test_n = re.match("test_920_(.+)", method.__name__).group(1)
        self.test_domain =  ("%s-" % self.test_n) + TestAuto.dns_uniq

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_920_001(self):
        # simple MD, drive it, check status before activation
        domain = self.test_domain
        dnsList = [ domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[], withSSL=True )
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        # we started without a valid certificate, so we expect /.httpd/certificate-status
        # to not give information about one and - since we waited for the ACME signup
        # to complete - to give information in 'staging' about the new cert.
        status = TestEnv.get_md_status( domain )
        assert not 'sha256-fingerprint' in status
        assert not 'valid-until' in status
        assert not 'valid-from' in status
        assert 'staging' in status
        assert 'valid-until' in status['staging']
        assert 'valid-from' in status['staging']
        assert 'sha256-fingerprint' in status['staging']
        # restart and activate
        # once activated, the staging must be gone and attributes exist for the active cert
        assert TestEnv.apache_restart() == 0
        status = TestEnv.get_md_status( domain )
        assert not 'staging' in status
        assert 'sha256-fingerprint' in status
        assert 'valid-until' in status
        assert 'valid-from' in status

    def test_920_002(self):
        # simple MD, drive it, manipulate staged credentials and check status
        domain = self.test_domain
        dnsList = [ domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[], withSSL=True )
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        # copy a real certificate from LE over to staging
        staged_cert = os.path.join(TestEnv.STORE_DIR, 'staging', domain, 'pubcert.pem') 
        real_cert = os.path.join('data', 'test_920', '002.pubcert')
        assert copyfile(real_cert, staged_cert) == None
        status = TestEnv.get_md_status( domain )
        # status shows the copied cert's properties as staged
        assert 'staging' in status
        assert 'Thu, 29 Aug 2019 16:06:35 GMT' == status['staging']['valid-until']
        assert 'Fri, 31 May 2019 16:06:35 GMT' == status['staging']['valid-from']
        assert '03039C464D454EDE79FCD2CAE859F668F269' ==  status['staging']['serial'] 
        assert 'sha256-fingerprint' in status['staging']
        assert len(status['staging']['scts']) == 2
        assert status['staging']['scts'][0]['logid'] == '747eda8331ad331091219cce254f4270c2bffd5e422008c6373579e6107bcc56'
        assert status['staging']['scts'][0]['signed'] == 'Fri, 31 May 2019 17:06:35 GMT'
        assert status['staging']['scts'][1]['logid'] == '293c519654c83965baaa50fc5807d4b76fbf587a2972dca4c30cf4e54547f478'
        assert status['staging']['scts'][1]['signed'] == 'Fri, 31 May 2019 17:06:35 GMT'
