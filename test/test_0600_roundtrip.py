# test mod_md basic configurations

import os
import pytest
import re
import socket
import ssl
import sys
import time

from datetime import datetime
from httplib import HTTPSConnection
from testbase import TestEnv
from testbase import CertUtil

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    # TestEnv.apache_err_reset()
    TestEnv.APACHE_CONF_SRC = "data/roundtrip"
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestRoundtrip:


    @classmethod
    def setup_class(cls):
        cls.dns_uniq = "%d.org" % time.time()
        cls.TMP_CONF = os.path.join(TestEnv.APACHE_CONF_SRC, "temp.conf")

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.check_acme()
        TestEnv.clear_store()
        if os.path.isfile(TestRoundtrip.TMP_CONF):
            os.remove(TestRoundtrip.TMP_CONF)
        TestEnv.install_test_conf(None);
        assert TestEnv.apache_start() == 0


    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add to store ---------

    def test_100(self):
        # test case: generate config with md -> restart -> drive -> generate config with vhost and ssl -> restart -> check HTTPS access
        domain = "test100-" + TestRoundtrip.dns_uniq
        # - generate config with one md
        dnsList = [ domain, "www." + domain ]
        self._append_conf_acme(TestRoundtrip.TMP_CONF)
        self._append_conf_admin(TestRoundtrip.TMP_CONF, "admin@" + domain)
        self._append_conf_md(TestRoundtrip.TMP_CONF, dnsList)
        # - restart, check that md is in store
        TestEnv.install_test_conf("temp");
        assert TestEnv.apache_restart() == 0
        self._check_md_names(domain, dnsList)
        # - drive
        assert TestEnv.a2md( [ "-v", "drive", domain ] )['rv'] == 0
        self._check_md_cert(dnsList)
        # - append vhost to config
        self._append_conf_vhost(TestRoundtrip.TMP_CONF, TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True)
        TestEnv.install_test_conf("temp");
        assert TestEnv.apache_restart() == 0
        # check: SSL is running OK
        test_url = "https://%s:%s/" % (domain, TestEnv.HTTPS_PORT)
        dnsResolve = "%s:%s:127.0.0.1" % (domain, TestEnv.HTTPS_PORT)
        assert TestEnv.run([ "curl", "--resolve", dnsResolve, "--cacert", TestEnv.path_domain_cert(domain), test_url])['rv'] == 0

    # --------- _utils_ ---------

    def _append_conf_acme(self, confPath):
        acmeConf = "MDCertificateAuthority %s\nMDCertificateProtocol ACME\nMDCertificateAgreement %s\n\n" % (TestEnv.ACME_URL, TestEnv.ACME_TOS)
        open(confPath, "a").write( acmeConf )

    def _append_conf_admin(self, confPath, email):
        open(confPath, "a").write("ServerAdmin mailto:%s\n\n" % email)

    def _append_conf_md(self, confPath, dnsList):
        open(confPath, "a").write("ManagedDomains %s\n\n" % " ".join(dnsList))

    def _append_conf_vhost(self, confPath, port, name, aliasList, withSSL):
        open(confPath, "a").write("<VirtualHost *:%s>\n    ServerName %s\n" % (port, name) )
        if len(aliasList) > 0:
            for alias in aliasList:
                open(confPath, "a").write("    ServerAlias %s\n" % alias )
        open(confPath, "a").write("    DocumentRoot htdocs\n\n")
        if withSSL:
            certPath = TestEnv.path_domain_cert(name)
            keyPath = TestEnv.path_domain_pkey(name)
            open(confPath, "a").write("    SSLEngine on\n    SSLCertificateFile %s\n    SSLCertificateKeyFile %s\n" % (certPath, keyPath) )
        
        open(confPath, "a").write("</VirtualHost>")


    def _check_md_names(self, name, dnsList):
        md = TestEnv.a2md([ "-j", "list", name ])['jout']['output'][0]
        assert md['name'] == name
        assert md['domains'] == dnsList

    def _check_md_cert(self, dnsList):
        name = dnsList[0]
        md = TestEnv.a2md([ "list", name ])['jout']['output'][0]
        # check tos agreement, cert url
        assert md['state'] == TestEnv.MD_S_COMPLETE
        assert "url" in md['cert']
        assert os.path.isfile( TestEnv.path_domain_pkey(name) )
        assert os.path.isfile( TestEnv.path_domain_cert(name) )
