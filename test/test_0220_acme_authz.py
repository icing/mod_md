# test mod_md acme authentications

import os.path
import json
import re
import sys
import time

from datetime import datetime
from shutil import copyfile
from testbase import TestEnv

def setup_module(module):
    TestEnv.init()
    assert TestEnv.is_live(TestEnv.ACME_URL, 1)
        
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)


class TestAuthz :

    def test_001(self):
        # register a new account, agree to tos, create auth resource
        domain = "www.test-example.org"
        run = TestEnv.a2md( 
            ["-t", TestEnv.ACME_TOS, "acme", "newreg", "tmp@example.org"], 
            raw=True )
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)

        run = TestEnv.a2md( ["acme", "authz", acct, domain], raw=True )
        assert run['rv'] == 0
        m = re.match("authz: " + domain + " (.*)$", run["stdout"])
        assert m
        authz_url = m.group(1)
        print "authz for %s at %s\n" % (domain, authz_url)

        assert TestEnv.get_json(authz_url, 5)["status"] == "pending"


