# test mod_md acme terms-of-service handling

import json
import re

from TestEnv import TestEnv


def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.initv1()
        
    
def teardown_module(module):
    print("teardown_module:%s" % module.__name__)


class TestAcmeToS:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.check_acme()
        TestEnv.clear_store()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # test case: register a new account with valid tos agreements
    def test_210_001(self):
        contact = "test210-001@not-forbidden.org"
        acct = self._prepare_account([contact], TestEnv.ACME_TOS)
        self._check_account(acct, ["mailto:" + contact], TestEnv.ACME_TOS)

    # test case: register a new account with valid tos agreements (short cli argument)
    def test_210_002(self):
        contact = "test210-002@not-forbidden.org"
        run = TestEnv.a2md(["-t", TestEnv.ACME_TOS, "acme", "newreg", contact], raw=True)
        assert run['rv'] == 0
        acct = re.match("registered: (.*)$", run['stdout']).group(1)
        self._check_account(acct, ["mailto:" + contact], TestEnv.ACME_TOS)
 
    # test case: register a new account with invalid tos agreements
    def test_210_003(self):
        run = TestEnv.a2md(["--terms", TestEnv.ACME_TOS2, "acme", "newreg", "test003@not-forbidden.org"])
        assert run["rv"] == 1
 
    # test case: register a new account with generic 'accepted'
    def test_210_003b(self):
        contact = "test003b@not-forbidden.org"
        run = TestEnv.a2md(["-t", "accepted", "acme", "newreg", contact])
        assert run["rv"] == 0
        acct = re.match("registered: (.*)", run['stdout']).group(1)
        self._check_account(acct, ["mailto:" + contact], TestEnv.ACME_TOS)
 
    # test case: register new account, agree to tos afterwards
    def test_210_004(self):
        contact = "test210-004@not-forbidden.org"
        acct = self._prepare_account([contact], None)
        self._check_account(acct, ["mailto:" + contact], None)
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS, "acme", "agree", acct])['rv'] == 0
        self._check_account(acct, ["mailto:" + contact], TestEnv.ACME_TOS)

    # test case: register new account, agree via 'accepted' afterwards
    def test_210_004b(self):
        contact = "test210-004@not-forbidden.org"
        acct = self._prepare_account([contact], None)
        self._check_account(acct, ["mailto:" + contact], None)
        assert TestEnv.a2md(["--terms", "accepted", "acme", "agree", acct])['rv'] == 0
        self._check_account(acct, ["mailto:" + contact], TestEnv.ACME_TOS)

    # test case: register new account, agree to wrong tos afterwards
    def test_210_005(self):
        contact = "test210-005@not-forbidden.org"
        acct = self._prepare_account([contact], None)
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS2, "acme", "agree", acct])['rv'] == 1
        self._check_account(acct, ["mailto:" + contact], None)

    # test case: agree to tos on non-existing account
    def test_210_006(self):
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS, "acme", "agree", "ACME-localhost-foo"])['rv'] == 1

    # test case: agree to tos on deleted account
    def test_210_007(self):
        contact = "test210-007@not-forbidden.org"
        acct = self._prepare_account([contact], None)
        assert TestEnv.a2md(["acme", "delreg", acct])['rv'] == 0
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS, "acme", "agree", acct])['rv'] == 1

    def _prepare_account(self, contact, tos):
        args = ["acme", "newreg"] + contact
        if tos:
            args = ["--terms", tos] + args
        run = TestEnv.a2md(args, raw=True)
        assert run['rv'] == 0
        return re.match("registered: (.*)$", run['stdout']).group(1)

    def _check_account(self, acct, contact, tos):
        with open(TestEnv.path_account(acct)) as f:
            acctj = json.load(f)
        assert acctj['registration']['contact'] == contact
        if tos:
            assert acctj['agreement'] == tos
        else:
            assert 'agreement' not in acctj
