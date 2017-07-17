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
from testbase import HttpdConf
from testbase import CertUtil

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.APACHE_CONF_SRC = "data/test_roundtrip"
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestRoundtrip:


    @classmethod
    def setup_class(cls):
        cls.dns_uniq = "%d.org" % time.time()
        cls.TMP_CONF = os.path.join(TestEnv.GEN_DIR, "roundtrip.conf")

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.check_acme()
        TestEnv.clear_store()
        TestEnv.install_test_conf(None);
        assert TestEnv.apache_start() == 0


    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add to store ---------

    def test_600_000(self):
        # test case: generate config with md -> restart -> drive -> generate config
        # with vhost and ssl -> restart -> check HTTPS access
        domain = "r000" + TestRoundtrip.dns_uniq
        dnsList = [ domain, "www." + domain ]

        # - generate config with one md
        conf = HttpdConf(TestRoundtrip.TMP_CONF, True)
        conf.add_admin("admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md(dnsList)
        conf.install()
        # - restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names(domain, dnsList)
        # - drive
        assert TestEnv.a2md( [ "-v", "drive", domain ] )['rv'] == 0
        self._check_md_cert(dnsList)
        # - append vhost to config
        conf.add_vhost(TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True)
        conf.install()
        assert TestEnv.apache_restart() == 0
        # check: SSL is running OK
        test_url = "https://%s:%s/" % (domain, TestEnv.HTTPS_PORT)
        dnsResolve = "%s:%s:127.0.0.1" % (domain, TestEnv.HTTPS_PORT)
        assert TestEnv.run([ "curl", "--resolve", dnsResolve, 
                            "--cacert", TestEnv.path_domain_cert(domain), test_url])['rv'] == 0

    def test_600_001(self):
        # test case: same as test_100, but with two parallel managed domains
        domainA = "r001a-" + TestRoundtrip.dns_uniq
        domainB = "r001b-" + TestRoundtrip.dns_uniq
        # - generate config with one md
        dnsListA = [ domainA, "www." + domainA ]
        dnsListB = [ domainB, "www." + domainB ]

        conf = HttpdConf(TestRoundtrip.TMP_CONF, True)
        conf.add_admin("admin@example.org")
        conf.add_drive_mode("manual")
        conf.add_md(dnsListA)
        conf.add_md(dnsListB)
        conf.install()

        # - restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names(domainA, dnsListA)
        self._check_md_names(domainB, dnsListB)

        # - drive
        assert TestEnv.a2md( [ "-vvv", "drive", domainA ] )['rv'] == 0
        assert TestEnv.a2md( [ "-vvv", "drive", domainB ] )['rv'] == 0
        self._check_md_cert(dnsListA)
        self._check_md_cert(dnsListB)

        # - append vhost to config
        conf.add_vhost(TestEnv.HTTPS_PORT, domainA, aliasList=[ dnsListA[1] ], withSSL=True)
        conf.add_vhost(TestEnv.HTTPS_PORT, domainB, aliasList=[ dnsListB[1] ], withSSL=True)
        conf.install()

        # check: SSL is running OK
        assert TestEnv.apache_restart() == 0
        test_url_a = "https://%s:%s/" % (domainA, TestEnv.HTTPS_PORT)
        test_url_b = "https://%s:%s/" % (domainB, TestEnv.HTTPS_PORT)
        dnsResolveA = "%s:%s:127.0.0.1" % (domainA, TestEnv.HTTPS_PORT)
        dnsResolveB = "%s:%s:127.0.0.1" % (domainB, TestEnv.HTTPS_PORT)
        assert TestEnv.run([ "curl", "--resolve", dnsResolveA, 
                            "--cacert", TestEnv.path_domain_cert(domainA), test_url_a])['rv'] == 0
        assert TestEnv.run([ "curl", "--resolve", dnsResolveB, 
                            "--cacert", TestEnv.path_domain_cert(domainB), test_url_b])['rv'] == 0

    def test_600_002(self):
        # test case: one md, that covers two vhosts
        domain = "r002-" + TestRoundtrip.dns_uniq
        nameA = "test-a." + domain
        nameB = "test-b." + domain
        dnsList = [ domain, nameA, nameB ]

        # - generate config with one md
        conf = HttpdConf(TestRoundtrip.TMP_CONF, True)
        conf.add_admin("admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md(dnsList)
        conf.install()
        
        # - restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names(domain, dnsList)

        # - drive
        assert TestEnv.a2md( [ "-vvv", "drive", domain ] )['rv'] == 0
        self._check_md_cert(dnsList)

        # - append vhost to config
        conf.add_vhost(TestEnv.HTTPS_PORT, nameA, aliasList=[], docRoot="htdocs/a", 
                       withSSL=True, certPath=TestEnv.path_domain_cert(domain), 
                       keyPath=TestEnv.path_domain_pkey(domain))
        conf.add_vhost(TestEnv.HTTPS_PORT, nameB, aliasList=[], docRoot="htdocs/b", 
                       withSSL=True, certPath=TestEnv.path_domain_cert(domain), 
                       keyPath=TestEnv.path_domain_pkey(domain))
        conf.install()
        
        # - create docRoot folder
        self._write_res_file(os.path.join(TestEnv.APACHE_HTDOCS_DIR, "a"), "name.txt", nameA)
        self._write_res_file(os.path.join(TestEnv.APACHE_HTDOCS_DIR, "b"), "name.txt", nameB)

        # check: SSL is running OK
        assert TestEnv.apache_restart() == 0
        test_url_a = "https://%s:%s/name.txt" % (nameA, TestEnv.HTTPS_PORT)
        test_url_b = "https://%s:%s/name.txt" % (nameB, TestEnv.HTTPS_PORT)
        dnsResolveA = "%s:%s:127.0.0.1" % (nameA, TestEnv.HTTPS_PORT)
        dnsResolveB = "%s:%s:127.0.0.1" % (nameB, TestEnv.HTTPS_PORT)
        result = TestEnv.run([ "curl", "--resolve", dnsResolveA, 
                              "--cacert", TestEnv.path_domain_cert(domain), test_url_a])
        assert result['rv'] == 0
        assert result['stdout'] == nameA
        result = TestEnv.run([ "curl", "--resolve", dnsResolveB, 
                              "--cacert", TestEnv.path_domain_cert(domain), test_url_b])
        assert result['rv'] == 0
        assert result['stdout'] == nameB

    # --------- _utils_ ---------

    def _write_res_file(self, docRoot, name, content):
        if not os.path.exists(docRoot):
            os.makedirs(docRoot)
        open(os.path.join(docRoot, name), "w").write(content)

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
