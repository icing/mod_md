# test driving the ACME protocol

import os.path
import re
import sys
import time
import json

from datetime import datetime
from testbase import TestEnv

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
    assert TestEnv.is_live(TestEnv.ACME_URL, 1)
    TestEnv.apache_err_reset()
    TestEnv.APACHE_CONF_SRC = "data/drive"
    status = TestEnv.apachectl("test1.example.org", "start")

def teardown_module(module):
    print("teardown_module:%s" % module.__name__)
    #status = TestEnv.apachectl(None, "stop")


class TestDrive :

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
        self.dns_uniq = "%d.org" % time.time()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- invalid precondition  ---------

    def test_100(self):
        # test case: md without contact info
        domain = "test100." + self.dns_uniq
        assert TestEnv.a2md( [ "add", domain ] )['rv'] == 0
        run = TestEnv.a2md( [ "drive", domain ] )
        assert run['rv'] == 1
        assert re.search("no contact information", run["stderr"])

    def test_101(self):
        # test case: md with contact, but without TOS
        domain = "test101." + self.dns_uniq
        assert TestEnv.a2md( [ "add", domain ] )['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", domain, "contacts", "admin@test1.example.org" ] 
            )['rv'] == 0
        run = TestEnv.a2md( [ "drive", domain ] )
        assert run['rv'] == 1
        assert re.search("need to accept terms-of-service", run["stderr"])

    def XXXXtest_102(self): # without URL it goes against the ACME LE production server
        # test case: md without ACME url
        domain = "test102." + self.dns_uniq
        assert TestEnv.run([TestEnv.A2MD, "-d", TestEnv.STORE_DIR, "-j", "add", domain])['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", domain, "contacts", "admin@test1.example.org" ] 
            )['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", domain, "agreement", TestEnv.ACME_TOS ] 
            )['rv'] == 0
        run = TestEnv.a2md( [ "drive", domain ] )
        assert run['rv'] == 1
        assert re.search("no CA server URL", run["stderr"])

    def test_103(self):
        # test case: md with unknown protocol FOO
        domain = "test103." + self.dns_uniq
        self._prepare_md([ domain ])
        assert TestEnv.a2md(
            [ "update", domain, "ca", TestEnv.ACME_URL, "FOO"]
            )['rv'] == 0
        run = TestEnv.a2md( [ "drive", domain ] )
        assert run['rv'] == 1
        assert re.search("unknown CA protocol", run["stderr"])

    # --------- driving OK  ---------

    def test_200(self):
        # test case: md with one domain
        domain = "test200." + self.dns_uniq
        self._prepare_md([ domain ])
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # drive
        assert TestEnv.a2md( [ "-vv", "drive", domain ] )['rv'] == 0
        self._check_md_cert(domain)

    def test_201(self):
        # test case: md with 2 domains
        domain = "test201." + self.dns_uniq
        self._prepare_md([ domain, "www." + domain ])
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # drive
        assert TestEnv.a2md( [ "-vv", "drive", domain ] )['rv'] == 0
        self._check_md_cert(domain)

    def test_202(self):
        # test case: md with one domain, local TOS agreement and ACME account
        # setup: create md
        domain = "test202." + self.dns_uniq
        self._prepare_md([ domain ])
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # setup: create account on server
        run = TestEnv.a2md( ["acme", "newreg", "admin@" + domain], raw=True )
        assert run['rv'] == 0
        acct = re.match("registered: (.*)$", run["stdout"]).group(1)
        # setup: link md to account
        assert TestEnv.a2md([ "update", domain, "account", acct])['rv'] == 0
        # drive
        run = TestEnv.a2md( [ "-vv", "drive", domain ] )
        print run["stderr"]
        assert run['rv'] == 0
        self._check_md_cert(domain)

    def test_203(self):
        # test case: md with one domain, ACME account and TOS agreement on server
        # setup: create md
        domain = "test202." + self.dns_uniq
        assert TestEnv.a2md(["add", domain])['rv'] == 0
        assert TestEnv.a2md([ "update", domain, "contacts", "admin@" + domain ])['rv'] == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # setup: create account on server
        run = TestEnv.a2md( ["acme", "newreg", "admin@" + domain], raw=True )
        assert run['rv'] == 0
        acct = re.match("registered: (.*)$", run["stdout"]).group(1)
        # setup: send TOS agreement to server
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS, "acme", "agree", acct])['rv'] == 0
        # setup: link md to account
        assert TestEnv.a2md([ "update", domain, "account", acct])['rv'] == 0
        # drive
        run = TestEnv.a2md( [ "-vv", "drive", domain ] )
        print run["stderr"]
        assert run['rv'] == 0
        self._check_md_cert(domain)

    def test_204(self):
        # test case: md with one domain, TOS agreement, ACME account and authz challenge
        # setup: create md
        domain = "test202." + self.dns_uniq
        self._prepare_md([ domain ])
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        # setup: create account on server
        run = TestEnv.a2md( ["acme", "newreg", "admin@" + domain], raw=True )
        assert run['rv'] == 0
        acct = re.match("registered: (.*)$", run["stdout"]).group(1)
        # setup: send TOS agreement to server
        assert TestEnv.a2md(["--terms", TestEnv.ACME_TOS, "acme", "agree", acct])['rv'] == 0
        # setup: link md to account
        assert TestEnv.a2md([ "update", domain, "account", acct])['rv'] == 0
        # setup: create authz resource, write it into store
        run = TestEnv.a2md( ["-vv", "acme", "authz", acct, domain], raw=True )
        assert run['rv'] == 0
        authz_url = re.match("authz: " + domain + " (.*)$", run["stdout"]).group(1)
        # TODO: find storage-independent way to modify local registration data
        jsonFile = TestEnv.STORE_DIR + "/domains/" + domain + "/authz.json"
        open(jsonFile, "w").write(json.dumps({
            "account": acct,
            "authorizations": [{
                "domain": domain,
                "location": authz_url,
                "state": 0
            }]
            }, indent=2))
        # drive
        run = TestEnv.a2md( [ "-vv", "drive", domain ] )
        print run["stderr"]
        assert run['rv'] == 0
        self._check_md_cert(domain)

    # --------- network problems  ---------

    def test_300(self):
        # test case: server not reachable
        domain = "test300." + self.dns_uniq
        self._prepare_md([ domain ])
        assert TestEnv.a2md(
            [ "update", domain, "ca", "http://localhost:4711/directory"]
            )['rv'] == 0
        # drive
        run = TestEnv.a2md( [ "drive", domain ] )
        assert run['rv'] == 1
        assert run['jout']['status'] == 61
        assert run['jout']['description'] == 'Connection refused'

    # --------- _utils_ ---------

    def _prepare_md(self, dnsList):
        assert TestEnv.a2md(["add"] + dnsList)['rv'] == 0
        assert TestEnv.a2md(
            [ "update", dnsList[0], "contacts", "admin@" + dnsList[0] ]
            )['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", dnsList[0], "agreement", TestEnv.ACME_TOS ]
            )['rv'] == 0

    def _check_md_cert(self, name):
        md = TestEnv.a2md([ "list", name ])['jout']['output'][0]
        assert "url" in md['cert']
        assert md['ca']['agreement'] == TestEnv.ACME_TOS
        # TODO: more specific checks on store data
