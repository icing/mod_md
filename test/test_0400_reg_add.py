# test mod_md acme terms-of-service handling

import json
import os.path
import re
import shutil
import subprocess
import sys
import time
import pytest

from ConfigParser import SafeConfigParser
from datetime import datetime
from httplib import HTTPConnection
from urlparse import urlparse
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
        
def teardown_module(module):
    print("teardown_module: %s" % module.__name__)


class TestReg :

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        # wipe store directory
        print("clear store dir: %s" % STORE_DIR)
        assert len(STORE_DIR) > 1
        shutil.rmtree(STORE_DIR, ignore_errors=True)
        os.makedirs(STORE_DIR)
 
    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add ---------

    def test_100(self):
        # test case: add a single dns managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns = "greenbytes.de"
        args.extend([ "add", dns ])
        run = TestUtil.run(args)
        jout1 = json.loads(run["stdout"])
        md = jout1['output'][0]
        assert md['name'] == dns
        assert len(md['domains']) == 1 
        assert md['domains'][0] == dns
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1
        # list store content
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        run = TestUtil.run(args)
        jout2 = json.loads(run["stdout"])
        assert jout1 == jout2

    def test_101(self):
        # test case: add > 1 dns managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        args.extend([ "add" ])
        args.extend(dns)
        run = TestUtil.run(args)
        jout1 = json.loads(run["stdout"])
        md = jout1['output'][0]
        assert md['name'] == dns[0]
        assert len(md['domains']) == 3 
        assert md['domains'] == dns
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1
        # list store content
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        run = TestUtil.run(args)
        jout2 = json.loads(run["stdout"])
        assert jout1 == jout2

    def test_102(self):
        # test case: add second managed domain
        # setup: add first managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns1 = [ "test-100.com", "test-101.com", "test-102.com" ]
        args.extend([ "add" ])
        args.extend(dns1)
        TestUtil.run(args)
        # add second managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        args.extend([ "add" ])
        args.extend(dns2)
        run = TestUtil.run(args)
        # assert: output covers only changed md
        jout = json.loads(run["stdout"])
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['name'] == dns2[0]
        assert md['domains'] == dns2
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1

    def test_103(self):
        # test case: add existing domain 
        # setup: add domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        args.extend([ "add"])
        dns = "greenbytes.de"
        args.extend([dns])
        TestUtil.run(args)
        # add same domain again
        run = TestUtil.run(args)
        assert run["rv"] == 1

    def test_104(self):
        # test case: add without CA URL
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        args.extend([ "add"])
        dns = "greenbytes.de"
        args.extend([dns])
        run = TestUtil.run(args)
        jout1 = json.loads(run["stdout"])
        assert len(jout1['output']) == 1
        md = jout1['output'][0]
        assert md['name'] == dns
        assert md['domains'] == [ dns ]
        assert "url" not in md['ca']
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1
        # list store content
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        run = TestUtil.run(args)
        jout2 = json.loads(run["stdout"])
        assert jout1 == jout2

    @pytest.mark.parametrize("invalidDNS", [
        ("tld"), ("white sp.ace"), ("*.wildcard.com"), ("k\xc3ller.idn.com")
    ])
    def test_105(self, invalidDNS):
        # test case: add with invalid DNS
        # dns as primary name
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        args.extend([ "add"])
        args.extend([ invalidDNS ])
        run = TestUtil.run(args)
        assert run["rv"] == 1
        # dns as alternate name
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        args.extend([ "add"])
        args.extend([ "test-100.de", invalidDNS ])
        run = TestUtil.run(args)
        assert run["rv"] == 1

    @pytest.mark.parametrize("invalidURL", [
        ("no.schema/path"), ("http://white space/path"), ("http://bad.port:-1/path")
    ])
    def test_106(self, invalidURL):
        # test case: add with invalid ACME URL
        args = [A2MD, "-a", invalidURL, "-d", STORE_DIR, "-j" ]
        dns = "greenbytes.de"
        args.extend([ "add", dns ])
        run = TestUtil.run(args)
        assert run["rv"] == 1

    def test_107(self):
        # test case: add overlapping dns names
        # setup: add first managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns1 = [ "test-100.com", "test-101.com" ]
        args.extend([ "add" ])
        args.extend(dns1)
        TestUtil.run(args)
        # 1: alternate DNS exists as primary name
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns2 = [ "greenbytes2.de", "test-100.com" ]
        args.extend([ "add" ])
        args.extend(dns2)
        run = TestUtil.run(args)
        assert run["rv"] == 1
        # 2: alternate DNS exists as alternate DNS
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns2 = [ "greenbytes2.de", "test-101.com" ]
        args.extend([ "add" ])
        args.extend(dns2)
        run = TestUtil.run(args)
        assert run["rv"] == 1
        # 3: primary name exists as alternate DNS
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns2 = [ "test-101.com" ]
        args.extend([ "add" ])
        args.extend(dns2)
        run = TestUtil.run(args)
        assert run["rv"] == 1

    def test_108(self):
        # test case: add subdomains as separate managed domain
        # setup: add first managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns1 = [ "test-100.com" ]
        args.extend([ "add" ])
        args.extend(dns1)
        TestUtil.run(args)
        # add second managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns2 = [ "sub.test-100.com" ]
        args.extend([ "add" ])
        args.extend(dns2)
        TestUtil.run(args)

    def test_109(self):
        # test case: add duplicate domain
        # setup: add managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns1 = "test-100.com"
        dns2 = "test-101.com"
        args.extend([ "add" ])
        args.extend([ dns1, dns2, dns1, dns2 ])
        run = TestUtil.run(args)
        # DNS is only listed once
        jout = json.loads(run["stdout"])
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == [ dns1, dns2 ]

    def test_110(self):
        # test case: add pnuycode name
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns = "xn--kller-jua.punycode.de"
        args.extend([ "add" ])
        args.extend([ dns, dns ])
        TestUtil.run(args)

    def test_111(self):
        # test case: don't sort alternate names
        # setup: add managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns = [ "test-100.com", "test-xxx.com", "test-aaa.com" ]
        args.extend([ "add" ])
        args.extend(dns)
        run = TestUtil.run(args)
        # DNS is only listed once
        jout = json.loads(run["stdout"])
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == dns

    # --------- list ---------

    def test_200(self):
        # test case: list empty store
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        run = TestUtil.run(args)
        jout = json.loads(run["stdout"])
        assert 'output' not in jout
        assert jout['status'] == 0

    def test_201(self):
        # test case: list two managed domains
        # setup: add managed domains
        dnslist = [ 
            [ "test-100.com", "test-101.com", "test-102.com" ],
            [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        ]
        for dns in dnslist:
            args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j", "add" ]
            args.extend(dns)
            TestUtil.run(args)
        # list all store content
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        run = TestUtil.run(args)
        jout = json.loads(run["stdout"])
        assert len(jout['output']) == len(dnslist)
        dnslist.reverse()
        for i in range (0, len(jout['output'])):
            md = jout['output'][i]
            assert md['name'] == dnslist[i][0]
            assert md['domains'] == dnslist[i]
            assert md['ca']['url'] == ACME_URL
            assert md['ca']['proto'] == 'ACME'
            assert md['state'] == 1
