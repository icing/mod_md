# test mod_md acme terms-of-service handling

import copy
import json
import re
import shutil
import sys
import time
import pytest

from datetime import datetime
from shutil import copyfile
from TestEnv import TestEnv

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


    # test case: add a single dns managed domain
    def test_100_000(self):
        dns = "greenbytes.de"
        jout1 = TestEnv.a2md( [ "add", dns ] )['jout']
        TestEnv.check_json_contains( jout1['output'][0],
            {
                "name": dns,
                "domains": [ dns ],
                "contacts": [],
                "ca": {
                    "url": TestEnv.ACME_URL,
                    "proto": "ACME"
                },
                "state": TestEnv.MD_S_INCOMPLETE
            })
        assert TestEnv.a2md( [ "list" ] )['jout'] == jout1

    # test case: add > 1 dns managed domain
    def test_100_001(self):
        dns = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        jout1 = TestEnv.a2md( [ "add" ] + dns )['jout']
        TestEnv.check_json_contains( jout1['output'][0],
            {
                "name": dns[0],
                "domains": dns,
                "contacts": [],
                "ca": {
                    "url": TestEnv.ACME_URL,
                    "proto": "ACME"
                },
                "state": TestEnv.MD_S_INCOMPLETE
            })
        assert TestEnv.a2md( [ "list" ] )['jout'] == jout1

    # test case: add second managed domain
    def test_100_002(self):
        dns1 = [ "test100-002.com", "test100-002a.com", "test100-002b.com" ]
        TestEnv.a2md( [ "add" ] + dns1 )
        # add second managed domain
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        jout = TestEnv.a2md( [ "add" ] + dns2 )['jout']
        # assert: output covers only changed md
        assert len(jout['output']) == 1
        TestEnv.check_json_contains( jout['output'][0],
            {
                "name": dns2[0],
                "domains": dns2,
                "contacts": [],
                "ca": {
                    "url": TestEnv.ACME_URL,
                    "proto": "ACME"
                },
                "state": TestEnv.MD_S_INCOMPLETE
            })
        assert len(TestEnv.a2md( [ "list" ] )['jout']['output']) == 2

    # test case: add existing domain 
    def test_100_003(self):
        dns = "greenbytes.de"
        assert TestEnv.a2md( [ "add", dns ] )['rv'] == 0
        assert TestEnv.a2md( [ "add", dns ] )['rv'] == 1

    # test case: add without CA URL
    def test_100_004(self):
        dns = "greenbytes.de"
        jout1 = TestEnv.run( [ TestEnv.A2MD, "-d", TestEnv.STORE_DIR, "-j", "add", dns ] )['jout']
        assert len(jout1['output']) == 1
        TestEnv.check_json_contains( jout1['output'][0],
            {
                "name": dns,
                "domains": [ dns ],
                "contacts": [],
                "ca": {
                    "proto": "ACME"
                },
                "state": TestEnv.MD_S_INCOMPLETE
            })
        assert TestEnv.a2md( [ "list" ] )['jout'] == jout1

    # test case: add with invalid DNS
    @pytest.mark.parametrize("invalidDNS", [
        ("tld"), ("white sp.ace"), ("invalid.*.wildcard.com"), ("k\xc3ller.idn.com")
    ])
    def test_100_005(self, invalidDNS):
        assert TestEnv.a2md( [ "add", invalidDNS ] )["rv"] == 1
        assert TestEnv.a2md( [ "add", "test-100.de", invalidDNS ] )["rv"] == 1

    # test case: add with invalid ACME URL
    @pytest.mark.parametrize("invalidURL", [
        ("no.schema/path"), ("http://white space/path"), ("http://bad.port:-1/path")
    ])
    def test_100_006(self, invalidURL):
        args = [TestEnv.A2MD, "-a", invalidURL, "-d", TestEnv.STORE_DIR, "-j" ]
        dns = "greenbytes.de"
        args.extend([ "add", dns ])
        assert TestEnv.run(args)["rv"] == 1

    # test case: add overlapping dns names
    def test_100_007(self):
        assert TestEnv.a2md( [ "add", "test-100.com", "test-101.com" ] )['rv'] == 0
        # 1: alternate DNS exists as primary name
        assert TestEnv.a2md( [ "add", "greenbytes2.de", "test-100.com" ] )['rv'] == 1
        # 2: alternate DNS exists as alternate DNS
        assert TestEnv.a2md( [ "add", "greenbytes2.de", "test-101.com" ] )['rv'] == 1
        # 3: primary name exists as alternate DNS
        assert TestEnv.a2md( [ "add", "test-101.com" ] )['rv'] == 1

    # test case: add subdomains as separate managed domain
    def test_100_008(self):
        assert TestEnv.a2md( [ "add", "test-100.com" ] )['rv'] == 0
        assert TestEnv.a2md( [ "add", "sub.test-100.com" ] )['rv'] == 0

    # test case: add duplicate domain
    def test_100_009(self):
        dns1 = "test-100.com"
        dns2 = "test-101.com"
        jout = TestEnv.a2md( [ "add", dns1, dns2, dns1, dns2 ] )['jout']
        # DNS is only listed once
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == [ dns1, dns2 ]

    # test case: add pnuycode name
    def test_100_010(self):
        assert TestEnv.a2md( [ "add", "xn--kller-jua.punycode.de" ] )['rv'] == 0

    # test case: don't sort alternate names
    def test_100_011(self):
        dns = [ "test-100.com", "test-xxx.com", "test-aaa.com" ]
        jout = TestEnv.a2md( [ "add" ] + dns )['jout']
        # DNS is only listed as specified
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == dns

    # test case: add DNS wildcard
    @pytest.mark.parametrize("wildDNS", [
        ("*.wildcard.com")
    ])
    def test_100_012(self, wildDNS):
        assert TestEnv.a2md(["add", wildDNS])['rv'] == 0
