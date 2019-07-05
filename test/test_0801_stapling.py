# test mod_md stapling support

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


class TestStapling:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.apache_err_reset();
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    #-----------------------------------------------------------------------------------------------
    # MD with stapling enabled, mod_ssl stapling off
    #@pytest.mark.skipif(True, reason="not implemented")
    def test_801_001(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line("MDStapling on")
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[])
        conf.install()

        # - restart (-> drive), check that md is in store
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        # the mod_md stapling should report success
        time.sleep(1)
        assert self.get_verify_response(domain) == "0 (ok)"
        assert self.get_ocsp_status(domain) == "successful (0x0)" 

    # --------- _utils_ ---------

    def get_client_status(self, domain):
        return TestEnv.run( [ "openssl", "s_client", "-status", 
                          "-connect", "%s:%s" % (TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT),
                          "-CAfile", "gen/ca.pem", 
                          "-servername", domain,
                          "-showcerts"
                          ] )
    
    def get_ocsp_status(self, domain):
        r = self.get_client_status( domain )
        regex = re.compile(r'OCSP response: +([^=\n]+)\n')
        matches = regex.finditer(r["stdout"])
        for m in matches:
            if m.group(1) != "":
                return m.group(1)
        regex = re.compile(r'OCSP Response Status:\s*(.+)')
        matches = regex.finditer(r["stdout"])
        for m in matches:
            if m.group(1) != "":
                return m.group(1)
        return None
        
    def get_verify_response(self, domain):
        r = self.get_client_status( domain )
        regex = re.compile(r'Verify return code:\s*(.+)')
        matches = regex.finditer(r["stdout"])
        for m in matches:
            if m.group(1) != "":
                return m.group(1)
        return None
