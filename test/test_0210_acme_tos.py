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
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
    assert TestEnv.is_live(TestEnv.ACME_URL, 1)
        
    
def teardown_module(module):
    print("teardown_module:%s" % module.__name__)

class TestAcmeToS :

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- acme tos ---------

    def test_001(self):
        # test case: register a new account with valid tos agreements
        contact = "test001@example.org"
        acct = self._prepare_account([contact], TestEnv.ACME_TOS)
        self._check_account(acct, ["mailto:" + contact], TestEnv.ACME_TOS)

    def test_002(self):
        # test case: register a new account with valid tos agreements (short cli argument)
        contact = "test002@example.org"
        run = TestEnv.a2md(["-t", TestEnv.ACME_TOS, "acme", "newreg", contact], raw=True )
        assert run['rv'] == 0
        acct = re.match("registered: (.*)$", run['stdout']).group(1)
        self._check_account(acct, ["mailto:" + contact], TestEnv.ACME_TOS)
 
    def test_003(self):
        # test case: register a new account with invalid tos agreements
        run = TestEnv.a2md(["--terms", TestEnv.ACME_TOS2, "acme", "newreg", "test003@example.org"])
        assert run["rv"] == 1
 
    def test_004(self):
        # test case: register new account, agree to tos afterwards
        contact = "test004@example.org"
        acct = self._prepare_account([contact], None)
        self._check_account(acct, ["mailto:" + contact], None)
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS, "acme", "agree", acct])['rv'] == 0
        self._check_account(acct, ["mailto:" + contact], TestEnv.ACME_TOS)

    def test_005(self):
        # test case: register new account, agree to wrong tos afterwards
        contact = "test005@example.org"
        acct = self._prepare_account([contact], None)
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS2, "acme", "agree", acct])['rv'] == 1
        self._check_account(acct, ["mailto:" + contact], None)

    def test_006(self):
        # test case: agree to tos on non-existing account
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS, "acme", "agree", "ACME-localhost-foo"])['rv'] == 1

    def test_007(self):
        # test case: agree to tos on deleted account
        contact = "test007@example.org"
        acct = self._prepare_account([contact], None)
        assert TestEnv.a2md( ["acme", "delreg", acct] )['rv'] == 0
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS, "acme", "agree", acct])['rv'] == 1

    # --------- _utils_ ---------

    def _prepare_account(self, contact, tos):
        args = [ "acme", "newreg"] + contact
        if tos:
            args = ["--terms", tos] + args
        run = TestEnv.a2md(args, raw=True )
        assert run['rv'] == 0
        return re.match("registered: (.*)$", run['stdout']).group(1)

    def _check_account(self, acct, contact, tos):
        # read account data from store
        # TODO: create a "a2md list accounts" command for this
        jout = TestEnv.run([ "cat", TestEnv.path_account(acct) ])['jout']
        assert jout['id'] == acct
        assert jout['registration']['contact'] == contact
        if tos:
            assert jout['agreement'] == tos
        else:
            assert 'agreement' not in jout
