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


class TestStore:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
 
    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_001(self):
        # verify expected binary version
        run = TestEnv.run([TestEnv.A2MD, "-V"])
        m = re.match("version: %s-git$" % 
            TestEnv.config.get('global', 'a2md_version'), run['stdout'])
        assert m

    def test_002(self):
        # verify that store is clean
        run = TestEnv.run(["find", TestEnv.STORE_DIR])
        assert re.match(TestEnv.STORE_DIR, run['stdout'])

    # --------- store add ---------

    def test_100(self):
        # test case: add a single dns managed domain
        dns = "greenbytes.de"
        assert TestEnv.a2md( [ "store", "add", dns ] )['jout']['output'][0] == {
            "name": dns,
            "domains": [ dns ],
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": 0,
            "drive": 0
        }

    def test_101(self):
        # test case: add > 1 dns managed domain
        dns = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        assert TestEnv.a2md( [ "store", "add" ] + dns )['jout']['output'][0] == {
            "name": dns[0],
            "domains": dns,
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": 0,
            "drive": 0
        }

    def test_102(self):
        # test case: add second managed domain
        # setup: add first managed domain
        dns1 = [ "test-100.com", "test-101.com", "test-102.com" ]
        assert TestEnv.a2md( [ "store", "add" ] + dns1 )['rv'] == 0
        
        # add second managed domain
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        jout = TestEnv.a2md( [ "store", "add" ] + dns2 )['jout']
        # assert: output covers only changed md
        assert len(jout['output']) == 1
        assert jout['output'][0] == {
            "name": dns2[0],
            "domains": dns2,
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": 0,
            "drive": 0
        }

    def test_103(self):
        # test case: add existing domain 
        # setup: add domain
        dns = "greenbytes.de"
        assert TestEnv.a2md( [ "store", "add", dns ] )['rv'] == 0
        # add same domain again
        assert TestEnv.a2md( [ "store", "add", dns ] )['rv'] == 1

    def test_104(self):
        # test case: add without CA URL
        dns = "greenbytes.de"
        args = [ TestEnv.A2MD, "-d", TestEnv.STORE_DIR, "-j", "store", "add", dns ]
        jout = TestEnv.run(args)['jout']
        assert len(jout['output']) == 1
        assert jout['output'][0] == {
            "name": dns,
            "domains": [ dns ],
            "contacts": [],
            "ca": {
                "proto": "ACME"
            },
            "state": 0,
            "drive": 0
        }

    # --------- store list ---------

    def test_200(self):
        # test case: list empty store
        assert TestEnv.a2md( [ "store", "list" ] )['jout'] == TestEnv.EMPTY_JOUT

    def test_201(self):
        # test case: list two managed domains
        # setup: add managed domains
        dnslist = [ 
            [ "test-100.com", "test-101.com", "test-102.com" ], 
            [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"] 
        ]
        for dns in dnslist:
            assert TestEnv.a2md( [ "store", "add" ] + dns )['rv'] == 0
        
        # list all store content
        jout = TestEnv.a2md( [ "store", "list" ] )['jout']
        assert len(jout['output']) == len(dnslist)
        dnslist.reverse()
        for i in range (0, len(jout['output'])):
            assert jout['output'][i] == {
                "name": dnslist[i][0],
                "domains": dnslist[i],
                "contacts": [],
                "ca": {
                    "url": TestEnv.ACME_URL,
                    "proto": "ACME"
                },
                "state": 0,
                "drive": 0
            }

    # --------- store remove ---------

    def test_300(self):
        # test case: remove managed domain
        # setup: store managed domain
        dns = "test-100.com"
        assert TestEnv.a2md( [ "store", "add", dns ] )['rv'] == 0
        # remove managed domain
        assert TestEnv.a2md( [ "store", "remove", dns ] )['jout'] == TestEnv.EMPTY_JOUT
        # list store content
        assert TestEnv.a2md( [ "store", "list" ] )['jout'] == TestEnv.EMPTY_JOUT

    def test_301(self):
        # test case: remove from list of managed domains 
        # setup: add several managed domains
        dns1 = [ "test-100.com", "test-101.com", "test-102.com" ]
        assert TestEnv.a2md( [ "store", "add"] + dns1 )['rv'] == 0
        
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        jout1 = TestEnv.a2md( [ "store", "add" ] + dns2 )['jout']
        # remove managed domain
        assert TestEnv.a2md( [ "store", "remove", "test-100.com" ] )['jout'] == TestEnv.EMPTY_JOUT
        # list store content
        assert TestEnv.a2md( [ "store", "list" ] )['jout'] == jout1

    def test_302(self):
        # test case: remove nonexisting managed domain
        # 1st try: error - not found
        dns1 = "test-100.com"
        run = TestEnv.a2md([ "store", "remove", dns1 ] )
        assert run['rv'] == 1
        assert run['jout'] == { 
            'status' : 2, 'description' : 'No such file or directory', 'output' : [] 
        }

    def test_303(self):
        # test case: force remove nonexisting managed domain
        dns1 = "test-100.com"
        assert TestEnv.a2md( [ "store", "remove", "-f", dns1 ] )['jout'] == TestEnv.EMPTY_JOUT

    # --------- store update ---------

    def test_400(self):
        # test case: null change
        # setup: store managed domain
        dns = "test-100.com"
        run1 = TestEnv.a2md( [ "store", "add", dns ] )
        # update without change
        assert TestEnv.a2md( [ "store", "update", dns ] )['jout'] == run1['jout']

    def test_401(self):
        # test case: add dns to managed domain
        # setup: store managed domain
        dns1 = "test-100.com"
        jout1 = TestEnv.a2md( [ "store", "add", dns1 ] )['jout']
        # add second dns
        dns2 = "test-101.com"
        args = [ "store", "update", dns1, "domains", dns1, dns2 ]
        assert TestEnv.a2md(args)['jout']['output'][0]['domains'] == [ dns1, dns2 ]

    def test_402(self):
        # test case: change CA URL
        # setup: store managed domain
        dns = "test-100.com"
        args = [ "store", "add", dns ]
        assert TestEnv.a2md(args)['jout']['output'][0]['ca']['url'] == TestEnv.ACME_URL
        # change CA URL
        nurl = "https://foo.com/"
        args = [TestEnv.A2MD, "-a", nurl, "-d", TestEnv.STORE_DIR, "-j", "store", "update", dns]
        assert TestEnv.run(args)['jout']['output'][0]['ca']['url'] == nurl

    def test_403(self):
        # test case: update nonexisting managed domain
        dns = "test-100.com"
        assert TestEnv.a2md( [ "store", "update", dns ] )['rv'] == 1

    def test_406(self):
        # test case: update domains, throw away md name
        # setup: store managed domain
        dns1 = "test-100.com"
        dns2 = "greenbytes.com"
        args = [ "store", "add", dns1 ]
        assert TestEnv.a2md(args)['jout']['output'][0]['domains'] == [ dns1 ]
        # override domains list
        args = [ "store", "update", dns1, "domains", dns2]
        assert TestEnv.a2md(args)['jout']['output'][0]['domains'] == [ dns2 ]

    def test_407(self):
        # test case: update domains with empty dns list
        # setup: store managed domain
        dns1 = "test-100.com"
        assert TestEnv.a2md( [ "store", "add", dns1 ] )['rv'] == 0
        # override domains list
        assert TestEnv.a2md( [ "store", "update", dns1, "domains" ] )['rv'] == 1
