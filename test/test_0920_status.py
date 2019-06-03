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

    def test_920_01(self):
        domain = self.test_domain
        
        # generate a simple MD
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
        assert TestEnv.apache_restart() == 0
        # once activated, the staging must be gone and attributes exist for the active cert
        status = TestEnv.get_md_status( domain )
        assert not 'staging' in status
        assert 'sha256-fingerprint' in status
        assert 'valid-until' in status
        assert 'valid-from' in status
