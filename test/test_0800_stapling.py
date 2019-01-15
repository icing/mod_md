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
        self.test_n = re.match("test_(.+)", method.__name__).group(1)
        self.test_domain =  ("%s-" % self.test_n) + TestAuto.dns_uniq

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    #-----------------------------------------------------------------------------------------------
    # MD with default, e.g. not staple
    # 
    def test_8001(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[], withSSL=True )
        conf.install()

        # - restart (-> drive), check that md is in store
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        self._check_md_cert( dns_list )
        cert1 = CertUtil( TestEnv.path_domain_pubcert(domain) )
        assert not cert1.get_must_staple()

    #-----------------------------------------------------------------------------------------------
    # MD that should explicitly not staple
    # 
    def test_8002(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_must_staple( "off" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[], withSSL=True )
        conf.install()

        # - restart (-> drive), check that md is in store
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        self._check_md_cert( dns_list )
        cert1 = CertUtil( TestEnv.path_domain_pubcert(domain) )
        assert not cert1.get_must_staple()
        assert self.get_ocsp_response(domain) == "no response sent" 

    #-----------------------------------------------------------------------------------------------
    # MD that must staple and toggle off again
    # 
    def test_8003(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_must_staple( "on" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[], withSSL=True )
        conf.install()

        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        self._check_md_cert( dns_list )
        cert1 = CertUtil( TestEnv.path_domain_pubcert(domain) )
        assert cert1.get_must_staple()

        # toggle MDMustStaple off, expect a cert that has it disabled
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_must_staple( "off" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[], withSSL=True )
        conf.install()

        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        self._check_md_cert( dns_list )
        cert1 = CertUtil( TestEnv.path_domain_pubcert(domain) )
        assert not cert1.get_must_staple()
    
        # toggle MDMustStaple on again, expect a cert that has it enabled
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_must_staple( "on" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[], withSSL=True )
        conf.install()

        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        self._check_md_cert( dns_list )
        cert1 = CertUtil( TestEnv.path_domain_pubcert(domain) )
        assert cert1.get_must_staple()

    #-----------------------------------------------------------------------------------------------
    # MD that must staple
    # 
    def test_8004(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_must_staple( "on" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[], withSSL=True )
        conf.install()

        # - restart (-> drive), check that md is in store
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        self._check_md_cert( dns_list )
        cert1 = CertUtil( TestEnv.path_domain_pubcert(domain) )
        assert cert1.get_must_staple()
        assert self.get_verify_response(domain) == "0 (ok)" 
        # enable once we implement ocsp stapling support
        # assert self.get_ocsp_response(domain) == "successful (0x0)" 

    # --------- _utils_ ---------

    def _check_md_cert(self, dns_list):
        name = dns_list[0]
        md = TestEnv.a2md([ "list", name ])['jout']['output'][0]
        # check tos agreement, cert url
        assert md['state'] == TestEnv.MD_S_COMPLETE
        assert os.path.isfile( TestEnv.path_domain_privkey(name) )
        assert os.path.isfile( TestEnv.path_domain_pubcert(name) )

    def get_client_status(self, domain):
        return TestEnv.run( [ "openssl", "s_client", "-status", 
                          "-connect", "%s:%s" % (TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT),
                          "-CAfile", "gen/ca.pem", 
                          "-servername", domain,
                          "-showcerts"
                          ] )
    
    def get_ocsp_response(self, domain):
        r = self.get_client_status( domain )
        regex = re.compile(r'OCSP response:\s*(.+)')
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
