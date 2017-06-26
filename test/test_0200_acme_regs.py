# test mod_md acme registrations

import os.path
import re
import sys
import time
import pytest
import json

from datetime import datetime
from shutil import copyfile
from testbase import TestEnv

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
    assert TestEnv.is_live(TestEnv.ACME_URL, 1)
        
    
def teardown_module(module):
    print("teardown_module:%s" % module.__name__)


class TestAcmeAcc :

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
 
    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- acme newreg ---------

    @pytest.mark.parametrize("contact", [
        ("x@example.org"), ("xx@example.org"), ("xxx@example.org")
    ])
    def test_100(self, contact):
        # test case: register a new account, vary length to check base64 encoding
        run = TestEnv.a2md( ["acme", "newreg", contact], raw=True )
        assert run['rv'] == 0
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)
        print "newreg: %s" % (m.group(1))
        # verify account in local store
        self._check_account(acct, ["mailto:" + contact])

    def test_101(self):
        # test case: respect 'mailto:' prefix in contact url
        contact = "mailto:xx@example.org"
        run = TestEnv.a2md( ["acme", "newreg", contact], raw=True )
        assert run['rv'] == 0
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)
        # verify account in local store
        self._check_account(acct, [contact])

    @pytest.mark.parametrize("invalidContact", [
        ("mehlto:xxx@example.org"), ("no.at.char"), ("with blank@test.com"), ("missing.host@"), ("@missing.localpart.de"), 
        ("double..dot@test.com"), ("double@at@test.com")
    ])
    def test_102(self, invalidContact):
        # test case: fail on invalid contact url
        assert TestEnv.a2md( ["acme", "newreg", invalidContact] )['rv'] == 1

    def test_103(self):
        # test case: use contact list
        contact = [ "xx@example.org", "aa@example.org" ]
        run = TestEnv.a2md( ["acme", "newreg"] + contact, raw=True )
        assert run['rv'] == 0
        m = re.match("registered: (.*)$", run["stdout"])
        assert m
        acct = m.group(1)
        # verify account in local store
        self._check_account(acct, ["mailto:" + contact[0], "mailto:" + contact[1]])


    # --------- acme validate ---------

    def test_200(self):
        # test case: validate new account
        acct = self._prepare_account(["tmp@example.org"])
        assert TestEnv.a2md( ["acme", "validate", acct] )['rv'] == 0

    def test_201(self):
        # test case: fail on non-existing account
        assert TestEnv.a2md( ["acme", "validate", "ACME-localhost-1000"] )['rv'] == 1

    def test_202(self):
        # test case: report fail on request signing problem
        # create new account
        acct = self._prepare_account(["tmp@example.org"])
        # modify server's reg url
        # TODO: find storage-independent way to modify local registration data
        jsonFile = TestEnv.path_account(acct)
        jout = TestEnv.run([ "cat", jsonFile ])['jout']
        jout['url'] = jout['url'] + "0"
        open(jsonFile, "w").write(json.dumps(jout))
        # validate accout
        assert TestEnv.a2md( ["acme", "validate", acct] )['rv'] == 1

    # --------- acme delreg ---------

    def test_300(self):
        # test case: register and try delete an account, will fail without persistence
        acct = self._prepare_account(["tmp@example.org"])
        assert TestEnv.a2md( ["delreg", acct] )['rv'] == 1

    def test_301(self):
        # test case: register and try delete an account with persistence
        acct = self._prepare_account(["tmp@example.org"])
        assert TestEnv.a2md( ["acme", "delreg", acct] )['rv'] == 0
        # check that store is clean
        # TODO: create a "a2md list accounts" command for this
        run = TestEnv.run(["find", TestEnv.STORE_DIR])
        assert re.match(TestEnv.STORE_DIR, run['stdout'])

    def test_302(self):
        # test case: delete a persisted account without specifying url
        acct = self._prepare_account(["tmp@example.org"])
        assert TestEnv.run([TestEnv.A2MD, "-d", TestEnv.STORE_DIR, "acme", "delreg", acct] )['rv'] == 0

    def test_303(self):
        # test case: delete, then validate an account
        acct = self._prepare_account(["test014@example.org"])
        assert TestEnv.a2md( ["acme", "delreg", acct] )['rv'] == 0
        # validate on deleted account fails
        assert TestEnv.a2md( ["acme", "validate", acct] )['rv'] == 1

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

