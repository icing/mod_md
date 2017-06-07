# test mod_md acme authentications

import os.path
import json
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
            c.close()
            return True
        except IOError:
            print "connect error:", sys.exc_info()[0]
            time.sleep(.1)
        except:
            print "Unexpected error:", sys.exc_info()[0]
    print "Unable to contact server after %d sec" % timeout
    return False

def get_json(url, timeout):
    server = urlparse(url)
    try_until = time.time() + timeout
    while time.time() < try_until:
        try:
            c = HTTPConnection(server.hostname, server.port, timeout=timeout)
            c.request('GET', server.path)
            resp = c.getresponse()
            data = json.loads(resp.read())
            c.close()
            return data
        except IOError:
            print "connect error:", sys.exc_info()[0]
            time.sleep(.1)
        except:
            print "Unexpected error:", sys.exc_info()[0]
    print "Unable to contact server after %d sec" % timeout
    return None

def setup_module(module):
    print("looking for ACME server at %s" % ACME_URL)
    assert check_live(ACME_URL, 1)
        
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)


class TestAuthz :

    def test_001(self):
        # register a new account, agree to tos, create auth resource
        domain = "www.test-example.org"
        args = [A2MD, "-a", ACME_URL, "-d", STORE_DIR, "-t", ACME_TOS]
        args.extend(["acme", "newreg", "tmp@example.org"])
        run = TestUtil.run(args)
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)

        args = [A2MD, "-d", STORE_DIR]
        args.extend(["acme", "authz", acct, domain])
        run = TestUtil.run(args)
        m = re.match("authz: " + domain + " (.*)$", run["stdout"])
        assert m
        authz_url = m.group(1)
        print "authz for %s at %s\n" % (domain, authz_url)

        resp = get_json(authz_url, 5)
        assert resp["status"] == "pending"


