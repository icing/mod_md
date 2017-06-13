# test mod_md acme terms-of-service handling

import os.path
import re
import sys
import time

from ConfigParser import SafeConfigParser
from datetime import datetime
from shutil import copyfile
from testbase import TestEnv

def setup_module(module):
    TestEnv.init()
    assert TestEnv.is_live(TestEnv.ACME_URL, 1)
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)


class TestAcmeToS :

    def test_001(self):
        # try register a new account with valid tos agreements
        run = TestEnv.a2md( [
            "--terms", TestEnv.ACME_TOS, "acme", "newreg", "test001@example.org"
        ], raw=True )
        assert run['rv'] == 0
        m = re.match("registered: (.*)$", run['stdout'])
        assert m
        print "newreg: %s" % (m.group(1))
 
    def test_002(self):
        # try register a new account with invalid tos agreements
        run = TestEnv.a2md( [
            "--terms", TestEnv.ACME_TOS2, "acme", "newreg", "test002@example.org"
        ])
        assert run["rv"] == 1
 
    def test_003(self):
        # register new account, agree to tos afterwards
        run = TestEnv.a2md( ["acme", "newreg", "test003@example.org"], raw=True )
        assert run['rv'] == 0
        m = re.match("registered: (.*)$", run['stdout'])
        assert m
        acct = m.group(1)
        assert TestEnv.a2md( ["--terms", TestEnv.ACME_TOS, "acme", "agree", acct] )['rv'] == 0

    def test_004(self):
        # register new account, agree to wrong tos afterwards
        run = TestEnv.a2md( ["acme", "newreg", "test004@example.org"], raw=True )
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)
        run = TestEnv.a2md( ["--terms", TestEnv.ACME_TOS2, "acme", "agree", acct] )
        assert run['rv'] == 1
