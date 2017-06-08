# test mod_md acme registrations

import os.path
import re
import sys
import time

from ConfigParser import SafeConfigParser
from datetime import datetime
from shutil import copyfile
from testbase import TestEnv

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
    assert TestEnv.is_live(TestEnv.ACME_URL, 1)
        
    
def teardown_module(module):
    print("teardown_module:%s" % module.__name__)


class TestRegs :

    def test_001(self):
        # try register a new account
        run = TestEnv.a2md( ["acme", "newreg", "xx@example.org"], raw=True )
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        print "newreg: %s" % (m.group(1))
 
    def test_002(self):
        # register with varying length to check our base64 encoding
        assert TestEnv.a2md( ["acme", "newreg", "x@example.org"] )['rv'] == 0

    def test_003(self):
        # register with varying length to check our base64 encoding
        assert TestEnv.a2md( ["acme", "newreg", "xxx@example.org"] )['rv'] == 0

    def test_004(self):
        # needs to fail on an invalid contact url
        assert TestEnv.a2md( ["acme", "newreg", "mehlto:xxx@example.org"] )['rv'] == 1

    def test_010(self):
        # register and try delete an account, will fail without persistence
        run = TestEnv.a2md( ["acme", "newreg", "tmp@example.org"], raw=True )
        assert run['rv'] == 0
        m = re.match("registered: (.*)$", run['stdout'])
        assert m
        acct = m.group(1)
        assert TestEnv.a2md( ["delreg", acct] )['rv'] == 1
        
    def test_012(self):
        # register and try delete an account with persistence
        run = TestEnv.a2md( ["acme", "newreg", "tmp@example.org"], raw=True )
        assert run['rv'] == 0
        m = re.match("registered: (.*)$", run['stdout'])
        assert m
        acct = m.group(1)
        assert TestEnv.a2md( ["acme", "delreg", acct] )['rv'] == 0

    def test_013(self):
        # delete a persisted account without specifying url
        run = TestEnv.a2md( ["acme", "newreg", "tmp@example.org"], raw=True )
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)
        assert TestEnv.a2md( ["acme", "delreg", acct] )['rv'] == 0

    def test_014(self):
        # create and validate an account
        run = TestEnv.a2md( ["acme", "newreg", "test014@example.org"], raw=True )
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)
        assert TestEnv.a2md( ["acme", "validate", acct] )['rv'] == 0


