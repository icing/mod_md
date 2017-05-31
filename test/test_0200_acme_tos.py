# test mod_md acme terms-of-service handling

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

A2MD = config.get('global', 'a2md_bin')
ACME_URL = config.get('acme', 'url')
ACME_TOS = config.get('acme', 'tos')
ACME_TOS2 = config.get('acme', 'tos2')
WEBROOT = config.get('global', 'server_dir')
ACME_DIR = os.path.join(WEBROOT, 'acme') 

CA1_DIR = os.path.join(ACME_DIR, 'server1')
CA2_DIR = os.path.join(ACME_DIR, 'server2')

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


class TestToS:

    def test_001(self):
        # try register a new account with valid tos agreements
        args = [A2MD, "-a", ACME_URL, "--terms", ACME_TOS ]
        args.extend(["acme", "newreg", "xx@example.org"])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 0
        m = re.match("registered: (.*)$", outdata)
        assert m
        print "newreg: %s" % (m.group(1))
 
    def test_002(self):
        # try register a new account with invalid tos agreements
        args = [A2MD, "-a", ACME_URL, "--terms", ACME_TOS2 ]
        args.extend(["acme", "newreg", "xx@example.org"])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 1
 
    def test_003(self):
        # register new account, agree to tos afterwards
        args = [A2MD, "-a", ACME_URL, "-d", CA1_DIR]
        args.extend(["acme", "newreg", "tmp@example.org"])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 0
        m = re.match("registered: (.*)$", outdata)
        assert m
        acct = m.group(1)
        args = [A2MD, "-d", CA1_DIR]
        args.extend(["acme", "agree", acct])
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 0
