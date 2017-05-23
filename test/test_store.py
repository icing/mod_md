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

def check_live(url, timeout):
    server = urlparse(url)
    try_until = time.time() + timeout
    while time.time() < try_until:
        try:
            c = HTTPConnection(server.hostname, server.port, timeout=timeout)
            c.request('HEAD', server.path)
            resp = c.getresponse()
            print "response %d %s" % (resp.status, resp.reason)
            c.close()
            return True
        except IOError:
            print "connect error:", sys.exc_info()[0]
            time.sleep(.1)
        except:
            print "Unexpected error:", sys.exc_info()[0]
    print "Unable to contact server after %d sec" % timeout
    return False

def setup_module(module):
    print("reset store dir %s" % STORE_DIR)
    assert len(STORE_DIR) > 1
    shutil.rmtree(STORE_DIR, ignore_errors=True)
    os.makedirs(STORE_DIR)
        
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)

class TestRegs:

    def test_001(self):
        # try add a single dns managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR ]
        dns1 = "greenbytes.de"
        args.extend([ "add", dns1 ])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 0
        md_file = os.path.join(STORE_DIR, 'domains', dns1, 'md.json')
        with open(md_file) as json_data:
            md = json.load(json_data)
            assert md['name'] == dns1
            assert len(md['domains']) == 1 
            assert md['domains'][0] == dns1
            assert md['ca']['url'] == ACME_URL
            assert md['ca']['proto'] == 'ACME'

    def test_002(self):
        # try add > 1 dns managed domain
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR ]
        dns1 = "greenbytes2.de"
        dns2 = "www.greenbytes2.de"
        dns3 = "mail.greenbytes2.de"
        args.extend([ "add", dns1, dns2, dns3 ])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 0
        md_file = os.path.join(STORE_DIR, 'domains', dns1, 'md.json')
        with open(md_file) as json_data:
            md = json.load(json_data)
            assert md['name'] == dns1
            assert len(md['domains']) == 3 
            assert md['domains'][0] == dns1
            assert md['domains'][1] == dns2
            assert md['domains'][2] == dns3
            assert md['ca']['url'] == ACME_URL
            assert md['ca']['proto'] == 'ACME'
