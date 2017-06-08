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
from testbase import TestEnv

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

A2MD = config.get('global', 'a2md_bin')
ACME_URL = config.get('acme', 'url')
WEBROOT = config.get('global', 'server_dir')
STORE_DIR = os.path.join(WEBROOT, 'md') 

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
        
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
            TestEnv.a2md( [ "add" ] + dns )

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- update ---------

    def test_100(self):
        # test case: update domains
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        dns = [ "foo.de", "bar.de" ]
        args.extend([ "update", self.NAME1, "domains" ])
        args.extend(dns)
        run = TestEnv.run(args)
        jout1 = json.loads(run["stdout"])
        md = jout1['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1
        # list store content
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        run = TestEnv.run(args)
        jout2 = json.loads(run["stdout"])
        assert md == jout2['output'][0]

    def test_101(self):
        # test case: remove all domains
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        args.extend([ "update", self.NAME1, "domains" ])
        run = TestEnv.run(args)
        assert run["rv"] == 1

    @pytest.mark.parametrize("invalidDNS", [
        ("tld"), ("white sp.ace"), ("*.wildcard.com"), ("k\xc3ller.idn.com")
    ])
    def test_102(self, invalidDNS):
        # test case: update domains with invalid DNS
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        args.extend([ "update", self.NAME1, "domains", invalidDNS ])
        run = TestEnv.run(args)
        assert run["rv"] == 1

    def test_103(self):
        # test case: update domains with overlapping DNS list
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        dns = [ self.NAME1, self.NAME2 ]
        args.extend([ "update", self.NAME1, "domains" ])
        args.extend(dns)
        run = TestEnv.run(args)
        assert run["rv"] == 1

    def test_104(self):
        # test case: update ca URL
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        url = "http://localhost.com:9999"
        args.extend([ "update", self.NAME1, "ca", url])
        run = TestEnv.run(args)
        jout1 = json.loads(run["stdout"])
        md = jout1['output'][0]
        assert md['name'] == self.NAME1
        assert md['ca']['url'] == url
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1

    @pytest.mark.parametrize("invalidURL", [
        ("no.schema/path"), ("http://white space/path"), ("http://bad.port:-1/path")
    ])
    def test_105(self, invalidURL):
        # test case: update ca with invalid URL
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        args.extend([ "update", self.NAME1, "ca", invalidURL])
        run = TestEnv.run(args)
        assert run["rv"] == 1

    def test_106(self):
        # test case: update with subdomains
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        dns = [ "test-foo.com", "sub.test-foo.com" ]
        args.extend([ "update", self.NAME1, "domains" ])
        args.extend(dns)
        run = TestEnv.run(args)
        jout1 = json.loads(run["stdout"])
        md = jout1['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    def test_107(self):
        # test case: update domains with duplicates
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        dns = [ self.NAME1, self.NAME1, self.NAME1 ]
        args.extend([ "update", self.NAME1, "domains" ])
        args.extend(dns)
        run = TestEnv.run(args)
        jout1 = json.loads(run["stdout"])
        md = jout1['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == [ self.NAME1 ]

    def test_108(self):
        # test case: remove domains with punycode
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        dns = [ self.NAME1, "xn--kller-jua.punycode.de" ]
        args.extend([ "update", self.NAME1, "domains" ])
        args.extend(dns)
        run = TestEnv.run(args)
        jout1 = json.loads(run["stdout"])
        md = jout1['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    def test_109(self):
        # test case: update non-existing managed domain
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        args.extend([ "update", "test-foo.com", "domains" ])
        run = TestEnv.run(args)
        assert run["rv"] == 1

    def test_110(self):
        # test case: update ca protocol
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        args.extend([ "update", self.NAME1, "ca", ACME_URL, "FOO"])
        run = TestEnv.run(args)
        jout1 = json.loads(run["stdout"])
        md = jout1['output'][0]
        assert md['name'] == self.NAME1
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'FOO'
        assert md['state'] == 1
