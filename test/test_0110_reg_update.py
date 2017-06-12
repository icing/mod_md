# test mod_md acme terms-of-service handling

import json
import re
import shutil
import sys
import time
import pytest

from datetime import datetime
from urlparse import urlparse
from testbase import TestEnv

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
    TestEnv.a2md_stdargs([TestEnv.A2MD, "-d", TestEnv.STORE_DIR, "-j" ])
    TestEnv.a2md_rawargs([TestEnv.A2MD, "-d", TestEnv.STORE_DIR ])

def teardown_module(module):
    print("teardown_module: %s" % module.__name__)


class TestReg :

    NAME1 = "greenbytes2.de"
    NAME2 = "test-100.com"

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
        # add managed domains
        dnslist = [ 
            [ self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            [ self.NAME2, "test-101.com", "test-102.com" ]
        ]
        for dns in dnslist:
            TestEnv.a2md( [ "-a", TestEnv.ACME_URL, "add" ] + dns )

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- update ---------

    def test_100(self):
        # test case: update domains
        dns = [ "foo.de", "bar.de" ]
        jout1 = TestEnv.a2md([ "update", self.NAME1, "domains" ] + dns)['jout']
        assert jout1['output'] == [{
            "name": self.NAME1,
            "domains": dns,
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": 1
        }]
        # list store content
        assert TestEnv.a2md(["list"])['jout']['output'][0] == jout1['output'][0]

    def test_101(self):
        # test case: remove all domains
        assert TestEnv.a2md(["update", self.NAME1, "domains"])['rv'] == 1

    @pytest.mark.parametrize("invalidDNS", [
        ("tld"), ("white sp.ace"), ("*.wildcard.com"), ("k\xc3ller.idn.com")
    ])
    def test_102(self, invalidDNS):
        # test case: update domains with invalid DNS
        assert TestEnv.a2md(["update", self.NAME1, "domains", invalidDNS])['rv'] == 1

    def test_103(self):
        # test case: update domains with overlapping DNS list
        dns = [ self.NAME1, self.NAME2 ]
        assert TestEnv.a2md(["update", self.NAME1, "domains"] + dns)['rv'] == 1

    def test_104(self):
        # test case: update CA URL
        url = "http://localhost.com:9999"
        jout = TestEnv.a2md([ "update", self.NAME1, "ca", url ])['jout']
        assert jout['output'] == [{
            "name": self.NAME1,
            "domains": [ self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [],
            "ca": {
                "url": url,
                "proto": "ACME"
            },
            "state": 1
        }]

    @pytest.mark.parametrize("invalidURL", [
        ("no.schema/path"), ("http://white space/path"), ("http://bad.port:-1/path")
    ])
    def test_105(self, invalidURL):
        # test case: update CA with invalid URL
        assert TestEnv.a2md(["update", self.NAME1, "ca", invalidURL])['rv'] == 1

    def test_106(self):
        # test case: update with subdomains
        dns = [ "test-foo.com", "sub.test-foo.com" ]
        md = TestEnv.a2md([ "update", self.NAME1, "domains" ] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    def test_107(self):
        # test case: update domains with duplicates
        dns = [ self.NAME1, self.NAME1, self.NAME1 ]
        md = TestEnv.a2md([ "update", self.NAME1, "domains" ] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == [ self.NAME1 ]

    def test_108(self):
        # test case: remove domains with punycode
        dns = [ self.NAME1, "xn--kller-jua.punycode.de" ]
        md = TestEnv.a2md([ "update", self.NAME1, "domains" ] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    def test_109(self):
        # test case: update non-existing managed domain
        assert TestEnv.a2md([ "update", "test-foo.com", "domains", "test-foo.com" ])['rv'] == 1

    def test_110(self):
        # test case: update ca protocol
        md = TestEnv.a2md([ "update", self.NAME1, "ca", TestEnv.ACME_URL, "FOO"])['jout']['output'][0]
        assert md['ca'] == {
            "url": TestEnv.ACME_URL,
            "proto": "FOO"
        }
        assert md['state'] == 1
