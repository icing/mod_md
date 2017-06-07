# test mod_md acme terms-of-service handling

import os.path
import re
import sys
import time

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
ACME_TOS = config.get('acme', 'tos')
ACME_TOS2 = config.get('acme', 'tos2')
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
    print("looking for ACME server at %s" % ACME_URL)
    assert check_live(ACME_URL, 1)
        
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)


class TestToS :

    def test_001(self):
        # try register a new account with valid tos agreements
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "--terms", ACME_TOS ]
        args.extend(["acme", "newreg", "xx@example.org"])
        run = TestUtil.run(args)
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        print "newreg: %s" % (m.group(1))
 
    def test_002(self):
        # try register a new account with invalid tos agreements
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "--terms", ACME_TOS2 ]
        args.extend(["acme", "newreg", "xx@example.org"])
        run = TestUtil.run(args)
        assert run["rv"] == 1
 
    def test_003(self):
        # register new account, agree to tos afterwards
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["acme", "newreg", "tmp@example.org"])
        run = TestUtil.run(args)
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)
        args = [A2MD, "-d", STORE_DIR]
        args.extend(["acme", "agree", acct])
        run = TestUtil.run(args)
