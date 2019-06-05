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
from test_base import TestEnv
from test_base import HttpdConf
from test_base import CertUtil

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.initv1()
    TestEnv.APACHE_CONF_SRC = "data/test_roundtrip"
    TestEnv.clear_store()
    TestEnv.install_test_conf(None);
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestRoundtripv1:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.check_acme()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add to store ---------

    def test_600_000(self):
        # test case: generate config with md -> restart -> drive -> generate config
        # with vhost and ssl -> restart -> check HTTPS access
        domain = self.test_domain
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf()
        conf.add_admin("admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md(dnsList)
        conf.install()
        # - restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(domain, dnsList)
        # - drive
        assert TestEnv.a2md([ "-vvvv", "drive", domain ])['rv'] == 0
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        # - append vhost to config
        conf.add_vhost(TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ])
        conf.install()
        assert TestEnv.apache_restart() == 0
        # check: SSL is running OK
        cert = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        assert domain in cert.get_san_list()

        # check file system permissions:
        TestEnv.check_file_permissions( domain )

    def test_600_001(self):
        # test case: same as test_600_000, but with two parallel managed domains
        domainA = "a-" + self.test_domain
        domainB = "b-" + self.test_domain
        dnsListA = [ domainA, "www." + domainA ]
        dnsListB = [ domainB, "www." + domainB ]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.add_drive_mode("manual")
        conf.add_md(dnsListA)
        conf.add_md(dnsListB)
        conf.install()

        # - restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(domainA, dnsListA)
        TestEnv.check_md(domainB, dnsListB)

        # - drive
        assert TestEnv.a2md( [ "drive", domainA ] )['rv'] == 0
        assert TestEnv.a2md( [ "drive", domainB ] )['rv'] == 0
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domainA)
        TestEnv.check_md_complete(domainB)

        # - append vhost to config
        conf.add_vhost(TestEnv.HTTPS_PORT, domainA, aliasList=[ dnsListA[1] ])
        conf.add_vhost(TestEnv.HTTPS_PORT, domainB, aliasList=[ dnsListB[1] ])
        conf.install()

        # check: SSL is running OK
        assert TestEnv.apache_restart() == 0
        certA = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domainA)
        assert dnsListA == certA.get_san_list()
        certB = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domainB)
        assert dnsListB == certB.get_san_list()

    def test_600_002(self):
        # test case: one md, that covers two vhosts
        domain = self.test_domain
        nameA = "a-" + domain
        nameB = "b-" + domain
        dnsList = [ domain, nameA, nameB ]
        conf = HttpdConf()
        conf.add_admin("admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md(dnsList)
        conf.install()
        
        # - restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(domain, dnsList)

        # - drive
        assert TestEnv.a2md( [ "drive", domain ] )['rv'] == 0
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)

        # - append vhost to config
        conf.add_vhost(TestEnv.HTTPS_PORT, nameA, aliasList=[], docRoot="htdocs/a")
        conf.add_vhost(TestEnv.HTTPS_PORT, nameB, aliasList=[], docRoot="htdocs/b")
        conf.install()
        
        # - create docRoot folder
        self._write_res_file(os.path.join(TestEnv.APACHE_HTDOCS_DIR, "a"), "name.txt", nameA)
        self._write_res_file(os.path.join(TestEnv.APACHE_HTDOCS_DIR, "b"), "name.txt", nameB)

        # check: SSL is running OK
        assert TestEnv.apache_restart() == 0
        certA = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, nameA)
        assert nameA in certA.get_san_list()
        certB = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, nameB)
        assert nameB in certB.get_san_list()
        assert certA.get_serial() == certB.get_serial()
        assert TestEnv.get_content(nameA, "/name.txt") == nameA
        assert TestEnv.get_content(nameB, "/name.txt") == nameB

    # --------- _utils_ ---------

    def _write_res_file(self, docRoot, name, content):
        if not os.path.exists(docRoot):
            os.makedirs(docRoot)
        open(os.path.join(docRoot, name), "w").write(content)

