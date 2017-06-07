# test mod_md acme terms-of-service handling

import json
import os.path
import re
import shutil
import sys
import time
import pytest

from ConfigParser import SafeConfigParser
from datetime import datetime
from shutil import copyfile
from testbase import TestUtil

config = SafeConfigParser()
config.read('test.ini')

PREFIX = config.get('global', 'prefix')
A2MD = config.get('global', 'a2md_bin')
ACME_URL = config.get('acme', 'url')
WEBROOT = config.get('global', 'server_dir')
STORE_DIR = os.path.join(WEBROOT, 'md') 

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestUtil.a2md_stdargs([A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ])
        
def teardown_module(module):
    print("teardown_module: %s" % module.__name__)


class TestStore:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        # wipe store directory
        print("clear store dir: %s" % STORE_DIR)
        assert len(STORE_DIR) > 1
        shutil.rmtree(STORE_DIR, ignore_errors=True)
        os.makedirs(STORE_DIR)
 
    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_001(self):
        # verify expected binary version
        run = TestUtil.run([A2MD, "-V"])
        m = re.match("version: %s-git$" % config.get('global', 'a2md_version'), run['stdout'])
        assert m

    # --------- store add ---------

    # add a single dns managed domain
    def test_100(self):
        dns = "greenbytes.de"
        md = TestUtil.a2md( [ "store", "add", dns ] )['jout']['output'][0]
        assert md['name'] == dns
        assert len(md['domains']) == 1 
        assert md['domains'][0] == dns
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 0

    # add > 1 dns managed domain
    def test_101(self):
        dns = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        md = TestUtil.a2md( [ "store", "add" ] + dns )['jout']['output'][0]
        assert md['name'] == dns[0]
        assert len(md['domains']) == 3 
        assert md['domains'] == dns
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 0

    # add second managed domain
    def test_102(self):
        # setup: add first managed domain
        dns1 = [ "test-100.com", "test-101.com", "test-102.com" ]
        assert TestUtil.a2md( [ "store", "add" ] + dns1 )['rv'] == 0
        
        # add second managed domain
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        jout = TestUtil.a2md( [ "store", "add" ] + dns2 )['jout']
        # assert: output covers only changed md
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['name'] == dns2[0]
        assert md['domains'] == dns2
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 0

    # add existing domain 
    def test_103(self):
        # setup: add domain
        dns = "greenbytes.de"
        assert TestUtil.a2md( [ "store", "add", dns ] )['rv'] == 0
        # add same domain again
        assert TestUtil.a2md( [ "store", "add", dns ] )['rv'] == 1

    # add without CA URL
    def test_104(self):
        dns = "greenbytes.de"
        args = [ A2MD, "-d", STORE_DIR, "-j", "store", "add", dns ]
        jout = TestUtil.run(args)['jout']
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['name'] == dns
        assert md['domains'] == [ dns ]
        assert "url" not in md['ca']
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 0

    # --------- store list ---------

    # list empty store
    def test_200(self):
        assert TestUtil.a2md( [ "store", "list" ] )['jout'] == { 'status' : 0 }

    # list two managed domains
    def test_201(self):
        # setup: add managed domains
        dnslist = [ 
            [ "test-100.com", "test-101.com", "test-102.com" ], 
            [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"] 
        ]
        for dns in dnslist:
            assert TestUtil.a2md( [ "store", "add" ] + dns )['rv'] == 0
        
        # list all store content
        jout = TestUtil.a2md( [ "store", "list" ] )['jout']
        assert len(jout['output']) == len(dnslist)
        dnslist.reverse()
        for i in range (0, len(jout['output'])):
            md = jout['output'][i]
            assert md['name'] == dnslist[i][0]
            assert md['domains'] == dnslist[i]
            assert md['ca']['url'] == ACME_URL
            assert md['ca']['proto'] == 'ACME'
            assert md['state'] == 0

    # --------- store remove ---------

    # remove managed domain
    def test_300(self):
        # setup: store managed domain
        dns = "test-100.com"
        assert TestUtil.a2md( [ "store", "add", dns ] )['rv'] == 0
        # remove managed domain
        assert TestUtil.a2md( [ "store", "remove", dns ] )['jout'] == { 'status' : 0 }
        # list store content
        assert TestUtil.a2md( [ "store", "list" ] )['jout'] == { 'status' : 0 }

    # remove from list of managed domains 
    def test_301(self):
        # setup: add several managed domains
        dns1 = [ "test-100.com", "test-101.com", "test-102.com" ]
        assert TestUtil.a2md( [ "store", "add"] + dns1 )['rv'] == 0
        
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        jout1 = TestUtil.a2md( [ "store", "add" ] + dns2 )['jout']
        # remove managed domain
        assert TestUtil.a2md( [ "store", "remove", "test-100.com" ] )['jout'] == { 'status' : 0 }
        # list store content
        assert TestUtil.a2md( [ "store", "list" ] )['jout'] == jout1

    # remove nonexisting managed domain
    def test_302(self):
	    # 1st try: error - not found
        dns1 = "test-100.com"
        run = TestUtil.a2md([ "store", "remove", dns1 ] )
        assert run['rv'] == 1
        assert run['jout'] == { 'status' : 2 }

    # force remove nonexisting managed domain
    def test_303(self):
        dns1 = "test-100.com"
        assert TestUtil.a2md( [ "store", "remove", "-f", dns1 ] )['jout'] == { 'status' : 0 }

    # --------- store update ---------

    # null change
    def test_400(self):
        # setup: store managed domain
        dns = "test-100.com"
        run1 = TestUtil.a2md( [ "store", "add", dns ] )
        # update without change
        assert TestUtil.a2md( [ "store", "update", dns ] )['jout'] == run1['jout']

    # add dns to managed domain
    def test_401(self):
        # setup: store managed domain
        dns1 = "test-100.com"
        jout1 = TestUtil.a2md( [ "store", "add", dns1 ] )['jout']
        # add second dns
        dns2 = "test-101.com"
        args = [ "store", "update", dns1, "domains", dns1, dns2 ]
        assert TestUtil.a2md(args)['jout']['output'][0]['domains'] == [ dns1, dns2 ]

    # change CA URL
    def test_402(self):
        # setup: store managed domain
        dns = "test-100.com"
        args = [ "store", "add", dns ]
        assert TestUtil.a2md(args)['jout']['output'][0]['ca']['url'] == ACME_URL
        # change CA URL
        nurl = "https://foo.com/"
        args = [A2MD, "-a", nurl, "-d", STORE_DIR, "-j", "store", "update", dns]
        assert TestUtil.run(args)['jout']['output'][0]['ca']['url'] == nurl

    # update nonexisting managed domain
    def test_403(self):
        dns = "test-100.com"
        assert TestUtil.a2md( [ "store", "update", dns ] )['rv'] == 1

    # update domains, throw away md name
    def test_406(self):
        # setup: store managed domain
        dns1 = "test-100.com"
        dns2 = "greenbytes.com"
        args = [ "store", "add", dns1 ]
        assert TestUtil.a2md(args)['jout']['output'][0]['domains'] == [ dns1 ]
        # override domains list
        args = [ "store", "update", dns1, "domains", dns2]
        assert TestUtil.a2md(args)['jout']['output'][0]['domains'] == [ dns2 ]

    # update domains with empty dns list
    def test_407(self):
        # setup: store managed domain
        dns1 = "test-100.com"
        assert TestUtil.a2md( [ "store", "add", dns1 ] )['rv'] == 0
        # override domains list
        assert TestUtil.a2md( [ "store", "update", dns1, "domains" ] )['rv'] == 1
