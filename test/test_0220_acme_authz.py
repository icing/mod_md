# test mod_md acme authentications

import os.path
import json
import re
import sys
import time

from datetime import datetime
from shutil import copyfile
from test_base import TestEnv

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.initv1()
        
    
def teardown_module(module):
    print("teardown_module:%s" % module.__name__)

class TestAcmeAuthz :

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.check_acme()
        TestEnv.clear_store()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # test case: create auth resource
    def test_220_001(self):
        acct = self._prepare_account(["tmp@not-forbidden.org"], TestEnv.ACME_TOS)
        domain = "www.test-not-forbidden.org"
        run = TestEnv.a2md( ["acme", "authz", acct, domain], raw=True )
        assert run['rv'] == 0
        m = re.match("authz: " + domain + " (.*)$", run["stdout"])
        assert m
        authz_url = m.group(1)
        print("authz for %s at %s\n" % (domain, authz_url))

        assert TestEnv.get_json(authz_url, 5)["status"] == "pending"

    def _prepare_account(self, contact, tos):
        args = [ "acme", "newreg"] + contact
        if tos:
            args = ["-t", tos] + args
        run = TestEnv.a2md(args, raw=True )
        assert run['rv'] == 0
        return re.match("registered: (.*)$", run['stdout']).group(1)

