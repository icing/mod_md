# test mod_md basic configurations

import os.path
import pytest
import re
import subprocess
import sys
import time

from ConfigParser import SafeConfigParser
from datetime import datetime
from httplib import HTTPConnection
from testbase import TestEnv

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.apache_err_reset()
    TestEnv.APACHE_CONF_SRC = "data/conf_store"
    status = TestEnv.apachectl(None, "start")
    assert status == 0
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    status = TestEnv.apachectl(None, "stop")


class TestConf:

    @classmethod
    def setup_class(cls):
        cls.dns_uniq = "%d.org" % time.time()

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        (self.errors, self.warnings) = TestEnv.apache_err_count()
        TestEnv.clear_store()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add to store ---------

    def test_001(self):
        # test case: no md definitions in config
        assert TestEnv.apachectl("empty", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        jout = TestEnv.a2md(["list"])['jout']
        assert "output" not in jout

    @pytest.mark.parametrize("confFile,dnsLists,mdCount", [
        ("test_001", [["example.org", "www.example.org", "mail.example.org"]], 1),
        ("test_002", [["example.org", "www.example.org", "mail.example.org"], ["example2.org", "www.example2.org", "mail.example2.org"]], 2)
    ])
    def test_100(self, confFile, dnsLists, mdCount):
        # test case: add md definitions on empty store
        assert TestEnv.apachectl(confFile, "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        for i in range (0, len(dnsLists)):
            self._check_md_names(dnsLists[i][0], dnsLists[i], 1, mdCount)

    def test_101(self):
        # test case: add managed domains as separate steps
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)
        assert TestEnv.apachectl("test_002", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 2)
        self._check_md_names("example2.org", ["example2.org", "www.example2.org", "mail.example2.org"], 1, 2)

    def test_102(self):
        # test case: add dns to existing md
        TestEnv.a2md([ "add", "example.org", "www.example.org" ])
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)

    def test_103(self):
        # test case: add new md definition with acme url, acme protocol
        assert TestEnv.apachectl("test_003", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        name = "example.org"
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, TestEnv.ACME_URL, "ACME")

    def test_104(self):
        # test case: add to existing md: acme url, acme protocol
        name = "example.org"
        assert TestEnv.apachectl("test_001", "graceful") == 0
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, TestEnv.ACME_URL_DEFAULT, "ACME")
        assert TestEnv.apachectl("test_003", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, TestEnv.ACME_URL, "ACME")

    def Xtest_105(self):
        # test case: add new md definition with server admin
        assert TestEnv.apachectl("test_004", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        name = "example.org"
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_contacts(name, ["admin@example.org"])

    def Xtest_106(self):
        # test case: add to existing md: server admin
        name = "example.org"
        TestEnv.a2md([name, "www.example.org", "mail.example.org"])
        assert TestEnv.apachectl("test_004", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_contacts(name, ["admin@example.org"])

    def Xtest_107(self):
        # test case: assign separate contact info based on VirtualHost
        assert TestEnv.apachectl("test_005", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        name1 = "example.org"
        name2 = "example2.org"
        self._check_md_names(name1, [name1, "www." + name1, "mail." + name1], 1, 2)
        self._check_md_names(name2, [name2, "www." + name2, "mail." + name2], 1, 2)
        self._check_md_contacts(name1, ["admin@" + name1])
        self._check_md_contacts(name2, ["admin@" + name2])

    # --------- remove from store ---------

    def Xtest_200(self):
        # test case: remove managed domain from config
        dnsList = ["example.org", "www.example.org", "mail.example.org"]
        TestEnv.a2md(["add"] + dnsList)
        self._check_md_names("example.org", dnsList, 1, 1)
        assert TestEnv.apachectl("empty", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # check: md stays in store
        self._check_md_names("example.org", dnsList, 1, 1)

    def Xtest_201(self):
        # test case: remove alias DNS from managed domain
        dnsList = ["example.org", "test.example.org", "www.example.org", "mail.example.org"]
        TestEnv.a2md(["add"] + dnsList)
        self._check_md_names("example.org", dnsList, 1, 1)
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # check: DNS stays part of md in store
        self._check_md_names("example.org", dnsList, 1, 1)

    def Xtest_202(self):
        # test case: remove primary name from managed domain
        dnsList = ["name.example.org", "example.org", "www.example.org", "mail.example.org"]
        TestEnv.a2md([ "add"] + dnsList)
        self._check_md_names("name.example.org", dnsList, 1, 1)
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # check: md stays with previous name, complete dns list
        self._check_md_names("name.example.org", dnsList, 1, 1)

    def Xtest_203(self):
        # test case: remove one md, keep another
        dnsList1 = ["greenybtes2.de", "www.greenybtes2.de", "mail.greenybtes2.de"]
        dnsList2 = ["example.org", "www.example.org", "mail.example.org"]
        TestEnv.a2md(["add"] + dnsList1)
        TestEnv.a2md(["add"] + dnsList2)
        self._check_md_names("greenybtes2.de", dnsList1, 1, 2)
        self._check_md_names("example.org", dnsList2, 1, 2)
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # all mds stay in store
        self._check_md_names("greenybtes2.de", dnsList1, 1, 2)
        self._check_md_names("example.org", dnsList2, 1, 2)

    def Xtest_204(self):
        # test case: remove ca info from md
        # setup: add md with ca info
        name = "example.org"
        assert TestEnv.apachectl("test_003", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # setup: sync with ca info removed
        assert TestEnv.apachectl("test_001", "graceful") == 0
        # check: md stays the same with previous ca info
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, TestEnv.ACME_URL, "ACME")

    def Xtest_205(self):
        # test case: remove server admin from md
        # setup: add md with admin info
        name = "example.org"
        assert TestEnv.apachectl("test_004", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # setup: sync with admin info removed
        assert TestEnv.apachectl("test_001", "graceful") == 0
        # check: md stays the same with previous admin info
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_contacts(name, ["admin@example.org"])

    # --------- change existing config definitions ---------

    def Xtest_300(self):
        # test case: reorder DNS names in md definition
        dnsList = ["example.org", "mail.example.org", "www.example.org"]
        TestEnv.a2md(["add"] + dnsList)
        self._check_md_names("example.org", dnsList, 1, 1)
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # check: dns list stays as before
        self._check_md_names("example.org", dnsList, 1, 1)

    def Xtest_301(self):
        # test case: move DNS from one md to another
        TestEnv.a2md([ "add", "example.org", "www.example.org", "mail.example.org", "mail.example2.org" ])
        TestEnv.a2md([ "add", "example2.org", "www.example2.org" ])
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org", "mail.example2.org"], 1, 2)
        self._check_md_names("example2.org", ["example2.org", "www.example2.org"], 1, 2)
        
        assert TestEnv.apachectl("test_002", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 2)
        self._check_md_names("example2.org", ["example2.org", "www.example2.org", "mail.example2.org"], 1, 2)

    def Xtest_302(self):
        # test case: change ca info
        # setup: add md with ca info
        name = "example.org"
        assert TestEnv.apachectl("test_003", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # setup: sync with changed ca info
        assert TestEnv.apachectl("test_006", "graceful") == 0
        # check: md stays the same with previous ca info
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, "http://localhost:6666/directory", "ACME")

    def Xtest_303(self):
        # test case: change server admin
        # setup: add md with admin info
        name = "example.org"
        assert TestEnv.apachectl("test_004", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # setup: sync with changed admin info
        assert TestEnv.apachectl("test_006", "graceful") == 0
        # check: md stays the same with previous admin info
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_contacts(name, ["webmaster@example.org"])

    # --------- status reset on critical store changes ---------

    def Xtest_400(self):
        # test case: add dns name on existing valid md
        # setup: create complete md in store
        domain = "test400-" + TestConf.dns_uniq
        name = "www." + domain
        assert TestEnv.a2md(["add", name])['rv'] == 0
        assert TestEnv.a2md([ "update", name, "contacts", "admin@" + name ])['rv'] == 0
        assert TestEnv.a2md([ "update", name, "agreement", TestEnv.ACME_TOS ])['rv'] == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # setup: drive it
        assert TestEnv.a2md( [ "drive", name ] )['rv'] == 0
        # setup: add second domain
        assert TestEnv.a2md([ "update", name, "domains", name, "test." + domain ])['rv'] == 0
        # check: state reset to INCOMPLETE
        md = TestEnv.a2md([ "list", name ])['jout']['output'][0]
        assert md['state'] == TestEnv.MD_S_INCOMPLETE

    def Xtest_401(self):
        # test case: change ca info
        # setup: create complete md in store
        domain = "test401-" + TestConf.dns_uniq
        name = "www." + domain
        assert TestEnv.a2md(["add", name])['rv'] == 0
        assert TestEnv.a2md([ "update", name, "contacts", "admin@" + name ])['rv'] == 0
        assert TestEnv.a2md([ "update", name, "agreement", TestEnv.ACME_TOS ])['rv'] == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # setup: drive it
        assert TestEnv.a2md( [ "drive", name ] )['rv'] == 0
        # setup: change CA URL
        assert TestEnv.a2md([ "update", name, "ca", TestEnv.ACME_URL_DEFAULT ])['rv'] == 0
        # check: state reset to INCOMPLETE
        md = TestEnv.a2md([ "list", name ])['jout']['output'][0]
        assert md['state'] == TestEnv.MD_S_INCOMPLETE

    # --------- _utils_ ---------

    def _new_errors(self):
        (errors, warnings) = TestEnv.apache_err_count()
        return errors - self.errors

    def _new_warnings(self):
        (errors, warnings) = TestEnv.apache_err_count()
        return warnings - self.warnings

    def _check_md_names(self, name, dnsList, state, mdCount):
        jout = TestEnv.a2md(["list"])['jout']
        assert jout
        output = jout['output']
        assert len(output) == mdCount
        mdFound = False
        for i in range (0, len(output)):
            md = output[i]
            if name == md['name']:
                mdFound = True
                assert md['state'] == TestEnv.MD_S_INCOMPLETE
                assert md['domains'] == dnsList
                assert md['state'] == state
        assert mdFound == True

    def _check_md_ca(self, name, ca_url, ca_proto):
        md = TestEnv.a2md(["list", name])['jout']['output'][0]
        if ca_url:
            assert md['ca']['url'] == ca_url
        else:
            assert "url" not in md['ca']
        if ca_proto:
            assert md['ca']['proto'] == ca_proto
        else:
            assert "proto" not in md['ca']

    def _check_md_contacts(self, name, contactList):
        md = TestEnv.a2md(["list", name])['jout']['output'][0]
        assert md['contacts'] == contactList
