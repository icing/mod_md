# test mod_md basic configurations

import os
import pytest
import re
import subprocess
import sys
import time

from ConfigParser import SafeConfigParser
from datetime import datetime
from httplib import HTTPConnection
from shutil import copyfile
from testbase import TestEnv

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.apache_err_reset()
    TestEnv.APACHE_CONF_SRC = "data/conf_store"
    TestEnv.install_test_conf(None);
    TestEnv.apache_start()
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    TestEnv.install_test_conf(None);
    TestEnv.apache_stop()


class TestConf:

    @classmethod
    def setup_class(cls):
        cls.dns_uniq = "%d.org" % time.time()

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.check_acme()
        TestEnv.clear_store()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add to store ---------

    def test_001(self):
        # test case: no md definitions in config
        TestEnv.install_test_conf("empty");
        assert TestEnv.apache_restart()
        jout = TestEnv.a2md(["list"])['jout']
        assert 0 == len(jout["output"])

    @pytest.mark.parametrize("confFile,dnsLists,mdCount", [
        ("test_001", [["example.org", "www.example.org", "mail.example.org"]], 1),
        ("test_002", [["example.org", "www.example.org", "mail.example.org"], ["example2.org", "www.example2.org", "mail.example2.org"]], 2)
    ])
    def test_100(self, confFile, dnsLists, mdCount):
        # test case: add md definitions on empty store
        TestEnv.install_test_conf(confFile);
        assert TestEnv.apache_restart()
        for i in range (0, len(dnsLists)):
            self._check_md_names(dnsLists[i][0], dnsLists[i], 1, mdCount)

    def test_101(self):
        # test case: add managed domains as separate steps
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart()
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)
        TestEnv.install_test_conf("test_002");
        assert TestEnv.apache_restart()
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 2)
        self._check_md_names("example2.org", ["example2.org", "www.example2.org", "mail.example2.org"], 1, 2)

    def test_102(self):
        # test case: add dns to existing md
        TestEnv.a2md([ "add", "example.org", "www.example.org" ])
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart()
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)

    def test_103(self):
        # test case: add new md definition with acme url, acme protocol
        TestEnv.install_test_conf("test_003");
        assert TestEnv.apache_restart()
        name = "example.org"
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, "http://acme.test.org:4000/directory", "ACME")

    def test_104(self):
        # test case: add to existing md: acme url, acme protocol
        name = "example.org"
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart()
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, TestEnv.ACME_URL_DEFAULT, "ACME")
        TestEnv.install_test_conf("test_003");
        assert TestEnv.apache_restart()
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, "http://acme.test.org:4000/directory", "ACME")

    def test_105(self):
        # test case: add new md definition with server admin
        TestEnv.install_test_conf("test_004");
        assert TestEnv.apache_restart()
        name = "example.org"
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_contacts(name, ["mailto:admin@example.org"])

    def test_106(self):
        # test case: add to existing md: server admin
        name = "example.org"
        TestEnv.a2md([name, "www.example.org", "mail.example.org"])
        TestEnv.install_test_conf("test_004");
        assert TestEnv.apache_restart()
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_contacts(name, ["mailto:admin@example.org"])

    def test_107(self):
        # test case: assign separate contact info based on VirtualHost
        # this config uses another store dir
        TestEnv.install_test_conf("test_005");
        assert TestEnv.apache_restart()
        name1 = "example.org"
        name2 = "example2.org"
        self._check_md_names(name1, [name1, "www." + name1, "mail." + name1], 1, 2)
        self._check_md_names(name2, [name2, "www." + name2, "mail." + name2], 1, 2)
        self._check_md_contacts(name1, ["mailto:admin@" + name1])
        self._check_md_contacts(name2, ["mailto:admin@" + name2])

    # --------- remove from store ---------

    def test_200(self):
        # test case: remove managed domain from config
        dnsList = ["example.org", "www.example.org", "mail.example.org"]
        TestEnv.a2md(["add"] + dnsList)
        self._check_md_names("example.org", dnsList, 1, 1)
        TestEnv.install_test_conf("empty");
        assert TestEnv.apache_restart()
        # check: md stays in store
        self._check_md_names("example.org", dnsList, 1, 1)

    def test_201(self):
        # test case: remove alias DNS from managed domain
        dnsList = ["example.org", "test.example.org", "www.example.org", "mail.example.org"]
        TestEnv.a2md(["add"] + dnsList)
        self._check_md_names("example.org", dnsList, 1, 1)
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart()
        # check: DNS stays part of md in store
        self._check_md_names("example.org", dnsList, 1, 1)

    def test_202(self):
        # test case: remove primary name from managed domain
        dnsList = ["name.example.org", "example.org", "www.example.org", "mail.example.org"]
        TestEnv.a2md([ "add"] + dnsList)
        self._check_md_names("name.example.org", dnsList, 1, 1)
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart()
        # check: md stays with previous name, complete dns list
        self._check_md_names("name.example.org", dnsList, 1, 1)

    def test_203(self):
        # test case: remove one md, keep another
        dnsList1 = ["greenybtes2.de", "www.greenybtes2.de", "mail.greenybtes2.de"]
        dnsList2 = ["example.org", "www.example.org", "mail.example.org"]
        TestEnv.a2md(["add"] + dnsList1)
        TestEnv.a2md(["add"] + dnsList2)
        self._check_md_names("greenybtes2.de", dnsList1, 1, 2)
        self._check_md_names("example.org", dnsList2, 1, 2)
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart()
        # all mds stay in store
        self._check_md_names("greenybtes2.de", dnsList1, 1, 2)
        self._check_md_names("example.org", dnsList2, 1, 2)

    def test_204(self):
        # test case: remove ca info from md, should fall back to default value
        # setup: add md with ca info
        name = "example.org"
        TestEnv.install_test_conf("test_003");
        assert TestEnv.apache_restart()
        # setup: sync with ca info removed
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart()
        # check: md stays the same with previous ca info
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, TestEnv.ACME_URL_DEFAULT, "ACME")

    def test_205(self):
        # test case: remove server admin from md
        # setup: add md with admin info
        name = "example.org"
        TestEnv.install_test_conf("test_004");
        assert TestEnv.apache_restart()
        # setup: sync with admin info removed
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart()
        # check: md stays the same with previous admin info
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_contacts(name, ["mailto:admin@example.org"])

    # --------- change existing config definitions ---------

    def test_300(self):
        # test case: reorder DNS names in md definition
        dnsList = ["example.org", "mail.example.org", "www.example.org"]
        TestEnv.a2md(["add"] + dnsList)
        self._check_md_names("example.org", dnsList, 1, 1)
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart()
        # check: dns list stays as before
        self._check_md_names("example.org", dnsList, 1, 1)

    def test_301(self):
        # test case: move DNS from one md to another
        TestEnv.a2md([ "add", "example.org", "www.example.org", "mail.example.org", "mail.example2.org" ])
        TestEnv.a2md([ "add", "example2.org", "www.example2.org" ])
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org", "mail.example2.org"], 1, 2)
        self._check_md_names("example2.org", ["example2.org", "www.example2.org"], 1, 2)
        
        TestEnv.install_test_conf("test_002");
        assert TestEnv.apache_restart()
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 2)
        self._check_md_names("example2.org", ["example2.org", "www.example2.org", "mail.example2.org"], 1, 2)

    def test_302(self):
        # test case: change ca info
        # setup: add md with ca info
        name = "example.org"
        TestEnv.install_test_conf("test_003");
        assert TestEnv.apache_restart()
        # setup: sync with changed ca info
        TestEnv.install_test_conf("test_006");
        assert TestEnv.apache_restart()
        # check: md stays the same with previous ca info
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_ca(name, "http://somewhere.com:6666/directory", "ACME")

    def test_303(self):
        # test case: change server admin
        # setup: add md with admin info
        name = "example.org"
        TestEnv.install_test_conf("test_004");
        assert TestEnv.apache_restart()
        # setup: sync with changed admin info
        TestEnv.install_test_conf("test_006");
        assert TestEnv.apache_restart()
        # check: md stays the same with previous admin info
        self._check_md_names(name, [name, "www.example.org", "mail.example.org"], 1, 1)
        self._check_md_contacts(name, ["mailto:webmaster@example.org"])

    # --------- status reset on critical store changes ---------

    def test_400(self):
        # test case: add dns name on existing valid md
        # setup: create complete md in store
        domain = "test400-" + TestConf.dns_uniq
        name = "www." + domain
        assert TestEnv.a2md(["add", name])['rv'] == 0
        assert TestEnv.a2md([ "update", name, "contacts", "admin@" + name ])['rv'] == 0
        assert TestEnv.a2md([ "update", name, "agreement", TestEnv.ACME_TOS ])['rv'] == 0
        assert TestEnv.apache_start()
        # setup: drive it
        assert TestEnv.a2md( [ "drive", name ] )['rv'] == 0
        # setup: add second domain
        assert TestEnv.a2md([ "update", name, "domains", name, "test." + domain ])['rv'] == 0
        # check: state reset to INCOMPLETE
        md = TestEnv.a2md([ "list", name ])['jout']['output'][0]
        assert md['state'] == TestEnv.MD_S_INCOMPLETE

    def test_401(self):
        # test case: change ca info
        # setup: create complete md in store
        domain = "test401-" + TestConf.dns_uniq
        name = "www." + domain
        assert TestEnv.a2md(["add", name])['rv'] == 0
        assert TestEnv.a2md([ "update", name, "contacts", "admin@" + name ])['rv'] == 0
        assert TestEnv.a2md([ "update", name, "agreement", TestEnv.ACME_TOS ])['rv'] == 0
        assert TestEnv.apache_start()
        # setup: drive it
        assert TestEnv.a2md( [ "drive", name ] )['rv'] == 0
        # setup: change CA URL
        assert TestEnv.a2md([ "update", name, "ca", TestEnv.ACME_URL_DEFAULT ])['rv'] == 0
        # check: state reset to INCOMPLETE
        md = TestEnv.a2md([ "list", name ])['jout']['output'][0]
        assert md['state'] == TestEnv.MD_S_COMPLETE

    # --------- configure another base dir ---------
    
    def test_500(self):
        TestEnv.install_test_conf("other_base");
        assert TestEnv.apache_restart()
        jout = TestEnv.a2md([ "list" ])['jout']
        assert len(jout['output']) == 0
        TestEnv.set_store_dir("md-other")
        self._check_md_names("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)

    

    # --------- _utils_ ---------

    def _check_md_names(self, name, dnsList, state, mdCount):
        jout = TestEnv.a2md([ "-j", "list" ])['jout']
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
