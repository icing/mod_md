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


class TestRegUpdate :

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

    # --------- update domains ---------

    def test_100(self):
        # test case: update domains
        dns = [ "foo.de", "bar.de" ]
        output1 = TestEnv.a2md([ "update", self.NAME1, "domains" ] + dns)['jout']['output']
        assert output1 == [{
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
        assert TestEnv.a2md(["list"])['jout']['output'][0] == output1[0]

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
        # test case: update with subdomains
        dns = [ "test-foo.com", "sub.test-foo.com" ]
        md = TestEnv.a2md([ "update", self.NAME1, "domains" ] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    def test_105(self):
        # test case: update domains with duplicates
        dns = [ self.NAME1, self.NAME1, self.NAME1 ]
        md = TestEnv.a2md([ "update", self.NAME1, "domains" ] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == [ self.NAME1 ]

    def test_106(self):
        # test case: remove domains with punycode
        dns = [ self.NAME1, "xn--kller-jua.punycode.de" ]
        md = TestEnv.a2md([ "update", self.NAME1, "domains" ] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    def test_107(self):
        # test case: update non-existing managed domain
        assert TestEnv.a2md([ "update", "test-foo.com", "domains", "test-foo.com" ])['rv'] == 1

    # --------- update ca ---------

    def test_200(self):
        # test case: update CA URL
        url = "http://localhost.com:9999"
        output = TestEnv.a2md([ "update", self.NAME1, "ca", url ])['jout']['output']
        assert output == [{
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
    def test_201(self, invalidURL):
        # test case: update CA with invalid URL
        assert TestEnv.a2md(["update", self.NAME1, "ca", invalidURL])['rv'] == 1

    def test_202(self):
        # test case: update ca protocol
        md = TestEnv.a2md([ "update", self.NAME1, "ca", TestEnv.ACME_URL, "FOO"])['jout']['output'][0]
        assert md['ca'] == {
            "url": TestEnv.ACME_URL,
            "proto": "FOO"
        }
        assert md['state'] == 1

    # --------- update account ---------

    def test_300(self):
        # test case: update account ID
        accID = "test.account.id"
        output = TestEnv.a2md([ "update", self.NAME1, "account", accID])['jout']['output']
        assert output == [{
            "name": self.NAME1,
            "domains": [ self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [],
            "ca": {
                "account": accID,
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": 1
        }]

    def test_301(self):
        # test case: remove account ID
        assert TestEnv.a2md([ "update", self.NAME1, "account", "test.account.id"])['rv'] == 0
        md = TestEnv.a2md([ "update", self.NAME1, "account"])['jout']['output'][0]
        assert md['ca'] == {
            "url": TestEnv.ACME_URL,
            "proto": "ACME"
        }
        assert md['state'] == 1

    def test_302(self):
        # test case: change existing account ID
        assert TestEnv.a2md([ "update", self.NAME1, "account", "test.account.id"])['rv'] == 0
        md = TestEnv.a2md([ "update", self.NAME1, "account", "foo.test.com"])['jout']['output'][0]
        assert md['ca'] == {
            "account": "foo.test.com",
            "url": TestEnv.ACME_URL,
            "proto": "ACME"
        }
        assert md['state'] == 1

    def test_303(self):
        # test case: ignore additional argument
        md = TestEnv.a2md([ "update", self.NAME1, "account", "test.account.id", "test2.account.id"])['jout']['output'][0]
        assert md['ca'] == {
            "account": "test.account.id",
            "url": TestEnv.ACME_URL,
            "proto": "ACME"
        }
        assert md['state'] == 1


    # --------- update contacts ---------

    def test_400(self):
        # test case: add contact info
        mail = "test@greenbytes.de"
        output = TestEnv.a2md([ "update", self.NAME1, "contacts", mail])['jout']['output']
        assert output == [{
            "name": self.NAME1,
            "domains": [ self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [ "mailto:" + mail ],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": 1
        }]

    def test_401(self):
        # test case: add multiple contact info, preserve order
        mail = [ "xxx@greenbytes.de", "aaa@greenbytes.de" ]
        md = TestEnv.a2md([ "update", self.NAME1, "contacts"] + mail)['jout']['output'][0]
        assert md['contacts'] == [ "mailto:" + mail[0], "mailto:" + mail[1] ]
        assert md['state'] == 1

    def test_402(self):
        # test case: must not remove contact info
        assert TestEnv.a2md([ "update", self.NAME1, "contacts", "test@greenbytes.de"])['rv'] == 0
        assert TestEnv.a2md([ "update", self.NAME1, "contacts"])['rv'] == 1

    def test_403(self):
        # test case: replace existing contact info
        assert TestEnv.a2md([ "update", self.NAME1, "contacts", "test@greenbytes.de"])['rv'] == 0
        md = TestEnv.a2md([ "update", self.NAME1, "contacts", "xxx@greenbytes.de"])['jout']['output'][0]
        assert md['contacts'] == [ "mailto:xxx@greenbytes.de"]
        assert md['state'] == 1

    @pytest.mark.parametrize("invalidMail", [
        ("no.at.char"), ("with blank@test.com"), ("missing.host@"), ("@missing.localpart.de"), 
        ("double..dot@test.com"), ("double@at@test.com")
    ])
    def test_404(self, invalidMail):
        # test case: use invalid mail address
        # SEI: Uhm, es ist nicht sinnvoll, eine komplette verification von
        # https://tools.ietf.org/html/rfc822 zu bauen.
        assert TestEnv.a2md([ "update", self.NAME1, "contacts", invalidMail])['rv'] == 1

    @pytest.mark.parametrize("url", [
        ("mailto:test@greenbytes.de"), ("wrong://schema@test.com")])
    def test_405(self, url):
        # test case: respect urls as given
        md = TestEnv.a2md([ "update", self.NAME1, "contacts", url])['jout']['output'][0]
        assert md['contacts'] == [ url ]
        assert md['state'] == 1

    # --------- update agreement ---------

    def test_500(self):
        # test case: add tos agreement
        output = TestEnv.a2md([ "update", self.NAME1, "agreement", TestEnv.ACME_TOS])['jout']['output']
        assert output == [{
            "name": self.NAME1,
            "domains": [ self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME",
                "agreement": TestEnv.ACME_TOS
            },
            "state": 1
        }]

    def test_501(self):
        # test case: update tos agreement
        assert TestEnv.a2md([ "update", self.NAME1, "agreement", TestEnv.ACME_TOS])['rv'] == 0
        md = TestEnv.a2md([ "update", self.NAME1, "agreement", TestEnv.ACME_TOS2])['jout']['output'][0]
        assert md['ca'] == {
            "url": TestEnv.ACME_URL,
            "proto": "ACME",
            "agreement": TestEnv.ACME_TOS2
        }
        assert md['state'] == 1

    def test_502(self):
        # test case: remove tos agreement
        assert TestEnv.a2md([ "update", self.NAME1, "agreement", TestEnv.ACME_TOS])['rv'] == 0
        md = TestEnv.a2md([ "update", self.NAME1, "agreement"])['jout']['output'][0]
        assert md['ca'] == {
            "url": TestEnv.ACME_URL,
            "proto": "ACME"
        }
        assert md['state'] == 1

    def test_503(self):
        # test case: ignore additional arguments
        md = TestEnv.a2md([ "update", self.NAME1, "agreement", TestEnv.ACME_TOS, TestEnv.ACME_TOS2])['jout']['output'][0]
        assert md['ca'] == {
            "url": TestEnv.ACME_URL,
            "proto": "ACME",
            "agreement": TestEnv.ACME_TOS
        }
        assert md['state'] == 1

    @pytest.mark.parametrize("invalidURL", [
        ("no.schema/path"), ("http://white space/path"), ("http://bad.port:-1/path")
    ])
    def test_504(self, invalidURL):
        # test case: update agreement with invalid URL
        assert TestEnv.a2md([ "update", self.NAME1, "agreement", invalidURL])['rv'] == 1

