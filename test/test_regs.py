# test mod_md acme registrations

import os.path
import re
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

ACME_DIRECTORY = config.get('acme', 'directory')

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
    print("looking for ACME server at %s" % ACME_DIRECTORY)
    assert check_live(ACME_DIRECTORY, 1)
        
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)


class TestRegs:

    def test_001(self):
        # try register a new account
        args = [A2MD, "-a", ACME_DIRECTORY]
        args.extend(["newreg", "xx@example.org"])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 0
        m = re.match("registered: (.*)$", outdata)
        assert m
        print "newreg: %s" % (m.group(1))
 
    def test_002(self):
        # register with varying length to check our base64 encoding
        args = [A2MD, "-a", ACME_DIRECTORY]
        args.extend(["newreg", "x@example.org"])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        p.communicate()
        assert p.wait() == 0

    def test_003(self):
        # register with varying length to check our base64 encoding
        args = [A2MD, "-a", ACME_DIRECTORY]
        args.extend(["newreg", "xxx@example.org"])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        p.communicate()
        assert p.wait() == 0

    def test_004(self):
        # needs to fail on an invalid contact url
        args = [A2MD, "-a", ACME_DIRECTORY]
        args.extend(["newreg", "mehlto:xxx@example.org"])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        p.communicate()
        assert p.wait() == 1

    def test_010(self):
        # register and try delete an account, will fail without persistence
        args = [A2MD, "-a", ACME_DIRECTORY]
        args.extend(["newreg", "tmp@example.org"])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 0
        m = re.match("registered: (.*)$", outdata)
        assert m
        acct = m.group(1)
        args = [A2MD, "-a", ACME_DIRECTORY]
        args.extend(["delreg", acct])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 1
        
 
