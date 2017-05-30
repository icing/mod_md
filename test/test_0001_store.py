# test mod_md acme terms-of-service handling

import json
import os.path
import re
import shutil
import subprocess
import sys
import time

from ConfigParser import SafeConfigParser
from datetime import datetime
from httplib import HTTPConnection
from urlparse import urlparse
from shutil import copyfile

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

A2MD = os.path.join(PREFIX, 'bin', 'a2md')
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
        args = [A2MD, "-V"]
        outdata = exec_sub(args)
        m = re.match("version: %s-git$" % config.get('global', 'a2md_version'), outdata)
        assert m

    # --------- store add ---------

    # test: add a single dns managed domain
    def test_100(self):
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns = "greenbytes.de"
        args.extend([ "store", "add", dns ])
        outdata = exec_sub(args)
        jout = json.loads(outdata)
        md = jout['output'][0]
        assert md['name'] == dns
        assert len(md['domains']) == 1 
        assert md['domains'][0] == dns
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'

    # test: add > 1 dns managed domain
    def test_101(self):
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        args.extend([ "store", "add" ])
        args.extend(dns)
        outdata = exec_sub(args)
        jout = json.loads(outdata)
        md = jout['output'][0]
        assert md['name'] == dns[0]
        assert len(md['domains']) == 3 
        assert md['domains'] == dns
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'

    # test: add second managed domain
    def test_102(self):
        # setup: add first managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns1 = [ "test-100.com", "test-101.com", "test-102.com" ]
        args.extend([ "store", "add" ])
        args.extend(dns1)
        outdata = exec_sub(args)
        # add second managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        args.extend([ "store", "add" ])
        args.extend(dns2)
        outdata = exec_sub(args)
        jout = json.loads(outdata)
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['name'] == dns2[0]
        assert md['domains'] == dns2
        assert md['ca']['url'] == ACME_URL
        assert md['ca']['proto'] == 'ACME'

    # --------- store remove ---------

    # test: remove managed domain
    def test_200(self):
        # setup: store managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns = "test-100.com"
        args.extend([ "store", "add", dns ])
        outdata = exec_sub(args)
        # remove managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        args.extend([ "store", "remove", dns ])
        outdata = exec_sub(args)
        jout = json.loads(outdata)
        assert 'output' not in jout
        assert jout['status'] == 0

    # test: remove from list of managed domains 
    def test_201(self):
        # setup: add several managed domains
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns1 = [ "test-100.com", "test-101.com", "test-102.com" ]
        args.extend([ "store", "add"])
        args.extend(dns1)
        exec_sub(args)
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns2 = [ "greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de" ]
        args.extend([ "store", "add" ])
        args.extend(dns2)
        outdata = exec_sub(args)
        # remove managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        args.extend([ "store", "remove", "test-100.com" ])
        outdata = exec_sub(args)
        jout = json.loads(outdata)
        assert 'output' not in jout
        assert jout['status'] == 0

    # test: remove nonexisting managed domain
    def test_202(self):
	    # 1st try: error - not found
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns1 = "test-100.com"
        args.extend([ "store", "remove", dns1 ])
        outdata = exec_sub_err(args, 1)
        jout = json.loads(outdata)
        assert 'output' not in jout
        assert jout['status'] == 2

    # test: force remove nonexisting managed domain
    def test_203(self):
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-j" ]
        dns1 = "test-100.com"
        args.extend([ "store", "remove", "-f", dns1 ])
        outdata = exec_sub(args)
        jout = json.loads(outdata)
        assert 'output' not in jout
        assert jout['status'] == 0
