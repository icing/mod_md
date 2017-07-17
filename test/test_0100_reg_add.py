# test mod_md acme terms-of-service handling

import json
import re
import shutil
import sys
import time
import pytest

from datetime import datetime
from shutil import copyfile
from testbase import TestEnv

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.init()

def teardown_module(module):
    print("teardown_module: %s" % module.__name__)


class TestRegAdd :

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
 
    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add ---------

    def test_100(self):
        # test case: add a single dns managed domain
        dns = "greenbytes.de"
        jout1 = TestEnv.a2md( [ "add", dns ] )['jout']
        assert jout1['output'][0] == {
            "name": dns,
            "domains": [ dns ],
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": TestEnv.MD_S_INCOMPLETE,
            "drive-mode": 0
        }
        # list store content
        assert TestEnv.a2md( [ "list" ] )['jout'] == jout1

    def test_101(self):
        # test case: add > 1 dns managed domain
        dns = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        jout1 = TestEnv.a2md( [ "add" ] + dns )['jout']
        assert jout1['output'][0] == {
            "name": dns[0],
            "domains": dns,
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": TestEnv.MD_S_INCOMPLETE,
            "drive-mode": 0
        }
        # list store content
        assert TestEnv.a2md( [ "list" ] )['jout'] == jout1

    def test_102(self):
        # test case: add second managed domain
        # setup: add first managed domain
        dns1 = [ "test-100.com", "test-101.com", "test-102.com" ]
        TestEnv.a2md( [ "add" ] + dns1 )
        # add second managed domain
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        jout = TestEnv.a2md( [ "add" ] + dns2 )['jout']
        # assert: output covers only changed md
        assert jout['output'] == [{
            "name": dns2[0],
            "domains": dns2,
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": TestEnv.MD_S_INCOMPLETE,
            "drive-mode": 0
        }]
        assert len(TestEnv.a2md( [ "list" ] )['jout']['output']) == 2

    def test_103(self):
        # test case: add existing domain 
        # setup: add domain
        dns = "greenbytes.de"
        assert TestEnv.a2md( [ "add", dns ] )['rv'] == 0
        # add same domain again
        assert TestEnv.a2md( [ "add", dns ] )['rv'] == 1

    def test_104(self):
        # test case: add without CA URL
        dns = "greenbytes.de"
        jout1 = TestEnv.run( [ TestEnv.A2MD, "-d", TestEnv.STORE_DIR, "-j", "add", dns ] )['jout']
        assert jout1['output'] == [{
            "name": dns,
            "domains": [ dns ],
            "contacts": [],
            "ca": {
                "proto": "ACME"
            },
            "state": TestEnv.MD_S_INCOMPLETE,
            "drive-mode": 0
        }]
        # list store content
        assert TestEnv.a2md( [ "list" ] )['jout'] == jout1

    @pytest.mark.parametrize("invalidDNS", [
        ("tld"), ("white sp.ace"), ("*.wildcard.com"), ("k\xc3ller.idn.com")
    ])
    def test_105(self, invalidDNS):
        # test case: add with invalid DNS
        # dns as primary name
        assert TestEnv.a2md( [ "add", invalidDNS ] )["rv"] == 1
        # dns as alternate name
        assert TestEnv.a2md( [ "add", "test-100.de", invalidDNS ] )["rv"] == 1

    @pytest.mark.parametrize("invalidURL", [
        ("no.schema/path"), ("http://white space/path"), ("http://bad.port:-1/path")
    ])
    def test_106(self, invalidURL):
        # test case: add with invalid ACME URL
        args = [TestEnv.A2MD, "-a", invalidURL, "-d", TestEnv.STORE_DIR, "-j" ]
        dns = "greenbytes.de"
        args.extend([ "add", dns ])
        assert TestEnv.run(args)["rv"] == 1

    def test_107(self):
        # test case: add overlapping dns names
        # setup: add first managed domain
        assert TestEnv.a2md( [ "add", "test-100.com", "test-101.com" ] )['rv'] == 0
        # 1: alternate DNS exists as primary name
        assert TestEnv.a2md( [ "add", "greenbytes2.de", "test-100.com" ] )['rv'] == 1
        # 2: alternate DNS exists as alternate DNS
        assert TestEnv.a2md( [ "add", "greenbytes2.de", "test-101.com" ] )['rv'] == 1
        # 3: primary name exists as alternate DNS
        assert TestEnv.a2md( [ "add", "test-101.com" ] )['rv'] == 1

    def test_108(self):
        # test case: add subdomains as separate managed domain
        # setup: add first managed domain
        assert TestEnv.a2md( [ "add", "test-100.com" ] )['rv'] == 0
        # add second managed domain
        assert TestEnv.a2md( [ "add", "sub.test-100.com" ] )['rv'] == 0

    def test_109(self):
        # test case: add duplicate domain
        # setup: add managed domain
        dns1 = "test-100.com"
        dns2 = "test-101.com"
        jout = TestEnv.a2md( [ "add", dns1, dns2, dns1, dns2 ] )['jout']
        # DNS is only listed once
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == [ dns1, dns2 ]

    def test_110(self):
        # test case: add pnuycode name
        assert TestEnv.a2md( [ "add", "xn--kller-jua.punycode.de" ] )['rv'] == 0

    def test_111(self):
        # test case: don't sort alternate names
        # setup: add managed domain
        dns = [ "test-100.com", "test-xxx.com", "test-aaa.com" ]
        jout = TestEnv.a2md( [ "add" ] + dns )['jout']
        # DNS is only listed as specified
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == dns

