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

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        (self.errors, self.warnings) = TestEnv.apache_err_count()
        TestEnv.clear_store()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add to store ---------

    def test_001(self):
        # test case: no md definitions in config
        assert TestEnv.apachectl("test_000", "graceful") == 0
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
            self._check_md(dnsLists[i][0], dnsLists[i], 1, mdCount)

    def test_101(self):
        # test case: add managed domains as separate steps
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)
        assert TestEnv.apachectl("test_002", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 2)
        self._check_md("example2.org", ["example2.org", "www.example2.org", "mail.example2.org"], 1, 2)

    def test_102(self):
        # test case: add dns to existing md
        TestEnv.a2md([ "add", "example.org", "www.example.org" ])
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)

    # --------- remove from store ---------

    def test_200(self):
        # test case: remove managed domain from store
        TestEnv.a2md([ "add", "example.org", "www.example.org", "mail.example.org" ])
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)
        assert TestEnv.apachectl("test_000", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # check: store is empty
        jout = TestEnv.a2md(["list"])['jout']
        assert "output" not in jout

    def test_201(self):
        # test case: remove alias DNS from managed domain
        TestEnv.a2md([ "add", "example.org", "test.example.org", "www.example.org", "mail.example.org" ])
        self._check_md("example.org", ["example.org", "test.example.org", "www.example.org", "mail.example.org"], 1, 1)
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)

    def test_202(self):
        # test case: remove primary name from managed domain
        TestEnv.a2md([ "add", "name.example.org", "example.org", "www.example.org", "mail.example.org" ])
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)

    def test_203(self):
        # test case: remove one md, keep another
        TestEnv.a2md([ "add", "greenybtes2.de", "www.greenybtes2.de", "mail.greenybtes2.de" ])
        TestEnv.a2md([ "add", "example.org", "www.example.org", "mail.example.org" ])
        self._check_md("greenybtes2.de", ["greenybtes2.de", "www.greenybtes2.de", "mail.greenybtes2.de"], 1, 2)
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 2)
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)

    # --------- reorder config definitions ---------

    def test_300(self):
        # test case: reorder DNS names in md definition
        TestEnv.a2md([ "add", "example.org", "mail.example.org", "www.example.org" ])
        self._check_md("example.org", ["example.org", "mail.example.org", "www.example.org"], 1, 1)
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 1)

    def test_301(self):
        # test case: move DNS from one md to another
        TestEnv.a2md([ "add", "example.org", "www.example.org", "mail.example.org", "mail.example2.org" ])
        TestEnv.a2md([ "add", "example2.org", "www.example2.org" ])
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org", "mail.example2.org"], 1, 2)
        self._check_md("example2.org", ["example2.org", "www.example2.org"], 1, 2)
        assert TestEnv.apachectl("test_002", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        self._check_md("example.org", ["example.org", "www.example.org", "mail.example.org"], 1, 2)
        self._check_md("example2.org", ["example2.org", "www.example2.org", "mail.example2.org"], 1, 2)

    # --------- status reset ---------

    #def test_400(self):
    #    # test case: status reset with config change
    #    assert 1 == 2


    # --------- _utils_ ---------

    def _new_errors(self):
        (errors, warnings) = TestEnv.apache_err_count()
        return errors - self.errors

    def _new_warnings(self):
        (errors, warnings) = TestEnv.apache_err_count()
        return warnings - self.warnings

    def _check_md(self, name, dnsList, state, mdCount):
        jout = TestEnv.a2md(["list"])['jout']
        assert jout
        output = jout['output']
        assert len(output) == mdCount
        mdFound = False
        for i in range (0, len(output)):
            md = output[i]
            if name == md['name']:
                mdFound = True
                assert md['domains'] == dnsList
                assert md['state'] == state
        assert mdFound == True