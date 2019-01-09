# test mod_md ACMEv2 registrations

import os.path
import re
import sys
import time
import pytest
import json
import pytest

from datetime import datetime
from shutil import copyfile
from test_base import TestEnv

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.initv2()

def teardown_module(module):
    print("teardown_module:%s" % module.__name__)


class TestAcmeAcc :

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.check_acme()
        TestEnv.clear_store()
 
    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- acme newreg ---------

    @pytest.mark.skipif(True, reason="not implemented")
    @pytest.mark.parametrize("contact", [
        ("x@not-forbidden.org"), ("xx@not-forbidden.org"), ("xxx@not-forbidden.org")
    ])
    def test_202_000(self, contact):
        # test case: register a new account, vary length to check base64 encoding
        run = TestEnv.a2md( ["-vvvvt", "accepted", "acme", "newreg", contact], raw=True )
        assert run['rv'] == 0
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)
        print "newreg: %s" % (m.group(1))
        # verify account in local store
        self._check_account(acct, ["mailto:" + contact])


    # --------- _utils_ ---------

    def _check_account(self, acct, contact):
        # read account data from store
        # TODO: create a "a2md list accounts" command for this
        jout = TestEnv.run([ "cat", TestEnv.path_account(acct) ])['jout']
        assert jout['id'] == acct
        assert jout['registration']['contact'] == contact

    def _prepare_account(self, contact):
        run = TestEnv.a2md( ["acme", "newreg"] + contact, raw=True )
        assert run['rv'] == 0
        return re.match("registered: (.*)$", run['stdout']).group(1)


