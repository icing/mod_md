# test mod_md acme registrations

import os.path
import re
import sys
import time

from ConfigParser import SafeConfigParser
from datetime import datetime
from httplib import HTTPConnection
from urlparse import urlparse
from shutil import copyfile
from testbase import BaseTest

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

A2MD = config.get('global', 'a2md_bin')
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
    print("setup_module: %s" % module.__name__)
    print("looking for ACME server at %s" % ACME_URL)
    assert check_live(ACME_URL, 1)
        
    
def teardown_module(module):
    print("teardown_module:%s" % module.__name__)


class TestRegs (BaseTest):

    def test_001(self):
        # try register a new account
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["acme", "newreg", "xx@example.org"])
        outdata = self.exec_sub(args)
        m = re.match("registered: (.*)$", outdata)
        assert m
        print "newreg: %s" % (m.group(1))
 
    def test_002(self):
        # register with varying length to check our base64 encoding
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["acme", "newreg", "x@example.org"])
        self.exec_sub(args)

    def test_003(self):
        # register with varying length to check our base64 encoding
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["acme", "newreg", "xxx@example.org"])
        self.exec_sub(args)

    def test_004(self):
        # needs to fail on an invalid contact url
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["acme", "newreg", "mehlto:xxx@example.org"])
        self.exec_sub_err(args, 1)

    def test_010(self):
        # register and try delete an account, will fail without persistence
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["acme", "newreg", "tmp@example.org"])
        outdata = self.exec_sub(args)
        m = re.match("registered: (.*)$", outdata)
        assert m
        acct = m.group(1)
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["delreg", acct])
        self.exec_sub_err(args, 1)
        
    def test_012(self):
        # register and try delete an account with persistence
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["acme", "newreg", "tmp@example.org"])
        outdata = self.exec_sub(args)
        m = re.match("registered: (.*)$", outdata)
        assert m
        acct = m.group(1)
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["acme", "delreg", acct])
        self.exec_sub(args)

    def test_013(self):
        # delete a persisted account without specifying url
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR]
        args.extend(["acme", "newreg", "tmp@example.org"])
        outdata = self.exec_sub(args)
        m = re.match("registered: (.*)$", outdata)
        assert m
        acct = m.group(1)
        args = [A2MD, "-d", STORE_DIR]
        args.extend(["acme", "delreg", acct])
        self.exec_sub(args)


