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

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

A2MD = config.get('global', 'a2md_bin')
ACME_URL = config.get('acme', 'url')
WEBROOT = config.get('global', 'server_dir')
STORE_DIR = os.path.join(WEBROOT, 'md') 

def exec_sub_err(args, errCode):
    print "execute: ", " ".join(args)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    (outdata, errdata) = p.communicate()
    assert p.wait() == errCode
    print "result:  (", errCode, ") ", outdata
    return outdata

def exec_sub(args):
    return exec_sub_err(args, 0)

def setup_module(module):
    print("setup_module: %s" % module.__name__)
        
def teardown_module(module):
    print("teardown_module: %s" % module.__name__)


class TestReg:

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
        args = [A2MD, "-V"]
        outdata = exec_sub(args)
        m = re.match("version: %s-git$" % config.get('global', 'a2md_version'), outdata)
        assert m

    # --------- add ---------

    # add a single dns managed domain
    def test_100(self):
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns = "greenbytes.de"
        args.extend([ "add", dns ])
        outdata = exec_sub(args)
        jout1 = json.loads(outdata)
        md = jout1['output'][0]
        assert md['name'] == dns
        assert len(md['domains']) == 1 
        assert md['domains'][0] == dns
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1
        # list store content
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        outdata = exec_sub(args)
        jout2 = json.loads(outdata)
        assert jout1 == jout2

    # add > 1 dns managed domain
    def test_101(self):
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        args.extend([ "add" ])
        args.extend(dns)
        outdata = exec_sub(args)
        jout1 = json.loads(outdata)
        md = jout1['output'][0]
        assert md['name'] == dns[0]
        assert len(md['domains']) == 3 
        assert md['domains'] == dns
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1
        # list store content
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        outdata = exec_sub(args)
        jout2 = json.loads(outdata)
        assert jout1 == jout2

    # add second managed domain
    def test_102(self):
        # setup: add first managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns1 = [ "test-100.com", "test-101.com", "test-102.com" ]
        args.extend([ "add" ])
        args.extend(dns1)
        exec_sub(args)
        # add second managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        args.extend([ "add" ])
        args.extend(dns2)
        outdata = exec_sub(args)
        # assert: output covers only changed md
        jout = json.loads(outdata)
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['name'] == dns2[0]
        assert md['domains'] == dns2
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1

    # add existing domain 
    def test_103(self):
        # setup: add domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        args.extend([ "add"])
        dns = "greenbytes.de"
        args.extend([dns])
        exec_sub(args)
        # add same domain again
        outdata = exec_sub_err(args, 1)

    # add without CA URL
    def test_104(self):
        args = [A2MD, "-d", STORE_DIR, "-j" ]
        args.extend([ "add"])
        dns = "greenbytes.de"
        args.extend([dns])
        outdata = exec_sub(args)
        jout1 = json.loads(outdata)
        assert len(jout1['output']) == 1
        md = jout1['output'][0]
        assert md['name'] == dns
        assert md['domains'] == [ dns ]
        assert "url" not in md['ca']
        assert md['ca']['proto'] == 'ACME'
        assert md['state'] == 1
        # list store content
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        outdata = exec_sub(args)
        jout2 = json.loads(outdata)
        assert jout1 == jout2

    # add with invalid DNS
    @pytest.mark.parametrize("invalidDNS", [
        ("tld"), ("white sp.ace")
    ])
    def test_105(self, invalidDNS):
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        args.extend([ "add"])
        args.extend([ invalidDNS ])
        exec_sub_err(args, 1)

    # add with invalid ACME URL
    @pytest.mark.parametrize("invalidURL", [
        ("no.schema/path"), ("http://white space/path"), ("http://bad.port:-1/path")
    ])
    def test_106(self, invalidURL):
        args = [A2MD, "-a", invalidURL, "-d", STORE_DIR, "-j" ]
        dns = "greenbytes.de"
        args.extend([ "add", dns ])
        exec_sub_err(args, 1)

    # --------- list ---------

    # list empty store
    def test_200(self):
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        outdata = exec_sub(args)
        jout = json.loads(outdata)
        assert 'output' not in jout
        assert jout['status'] == 0

    # list two managed domains
    def test_201(self):
        # setup: add managed domains
        dnslist = [ 
            [ "test-100.com", "test-101.com", "test-102.com" ], 
            [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"] 
        ]
        for dns in dnslist:
            args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j", "add" ]
            args.extend(dns)
            exec_sub(args)
        # list all store content
        args = [A2MD, "-d", STORE_DIR, "-j", "list" ]
        outdata = exec_sub(args)
        jout = json.loads(outdata)
        assert len(jout['output']) == len(dnslist)
        dnslist.reverse()
        for i in range (0, len(jout['output'])):
            md = jout['output'][i]
            assert md['name'] == dnslist[i][0]
            assert md['domains'] == dnslist[i]
            assert md['ca']['url'] == ACME_URL
            assert md['ca']['proto'] == 'ACME'
            assert md['state'] == 1
