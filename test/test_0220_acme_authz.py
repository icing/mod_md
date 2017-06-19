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
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
    assert TestEnv.is_live(TestEnv.ACME_URL, 1)
        
    
def teardown_module(module):
    print("teardown_module:%s" % module.__name__)

class TestAcmeAuthz :

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- acme authz ---------

    def test_001(self):
        # test case: create auth resource
        # setup: register a new account, agree to tos
        acct = self._prepare_account(["tmp@example.org"], TestEnv.ACME_TOS)
        domain = "www.test-example.org"
        run = TestEnv.a2md( ["acme", "authz", acct, domain], raw=True )
        assert run['rv'] == 0
        m = re.match("authz: " + domain + " (.*)$", run["stdout"])
        assert m
        authz_url = m.group(1)
        print "authz for %s at %s\n" % (domain, authz_url)

        assert TestEnv.get_json(authz_url, 5)["status"] == "pending"

    # --------- _utils_ ---------

    def _prepare_account(self, contact, tos):
        args = [ "acme", "newreg"] + contact
        if tos:
            args = ["-t", tos] + args
        run = TestEnv.a2md(args, raw=True )
        assert run['rv'] == 0
        return re.match("registered: (.*)$", run['stdout']).group(1)

