# test mod_md acme terms-of-service handling

import pytest

from TestEnv import TestEnv


def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
    TestEnv.a2md_stdargs([TestEnv.A2MD, "-d", TestEnv.STORE_DIR, "-j"])
    TestEnv.a2md_rawargs([TestEnv.A2MD, "-d", TestEnv.STORE_DIR])


def teardown_module(module):
    print("teardown_module: %s" % module.__name__)


class TestRegUpdate:

    NAME1 = "greenbytes2.de"
    NAME2 = "test-100.com"

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
        # add managed domains
        domains = [ 
            [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            [self.NAME2, "test-101.com", "test-102.com"]
        ]
        for dns in domains:
            TestEnv.a2md(["-a", TestEnv.ACME_URL, "add"] + dns)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # test case: update domains
    def test_110_000(self):
        dns = ["foo.de", "bar.de"]
        output1 = TestEnv.a2md(["-vvvv", "update", self.NAME1, "domains"] + dns)['jout']['output']
        assert len(output1) == 1
        TestEnv.check_json_contains(output1[0], {
            "name": self.NAME1,
            "domains": dns,
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": TestEnv.MD_S_INCOMPLETE
        })
        assert TestEnv.a2md(["list"])['jout']['output'][0] == output1[0]

    # test case: remove all domains
    def test_110_001(self):
        assert TestEnv.a2md(["update", self.NAME1, "domains"])['rv'] == 1

    # test case: update domains with invalid DNS
    @pytest.mark.parametrize("invalid_dns", [
        "tld", "white sp.ace", "invalid.*.wildcard.com", "k\xc3ller.idn.com"
    ])
    def test_110_002(self, invalid_dns):
        assert TestEnv.a2md(["update", self.NAME1, "domains", invalid_dns])['rv'] == 1

    # test case: update domains with overlapping DNS list
    def test_110_003(self):
        dns = [self.NAME1, self.NAME2]
        assert TestEnv.a2md(["update", self.NAME1, "domains"] + dns)['rv'] == 1

    # test case: update with subdomains
    def test_110_004(self):
        dns = ["test-foo.com", "sub.test-foo.com"]
        md = TestEnv.a2md(["update", self.NAME1, "domains"] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    # test case: update domains with duplicates
    def test_110_005(self):
        dns = [self.NAME1, self.NAME1, self.NAME1]
        md = TestEnv.a2md(["update", self.NAME1, "domains"] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == [self.NAME1]

    # test case: remove domains with punycode
    def test_110_006(self):
        dns = [self.NAME1, "xn--kller-jua.punycode.de"]
        md = TestEnv.a2md(["update", self.NAME1, "domains"] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    # test case: update non-existing managed domain
    def test_110_007(self):
        assert TestEnv.a2md(["update", "test-foo.com", "domains", "test-foo.com"])['rv'] == 1

    # test case: update domains with DNS wildcard
    @pytest.mark.parametrize("wild_dns", [
        "*.wildcard.com"
    ])
    def test_110_008(self, wild_dns):
        assert TestEnv.a2md(["update", self.NAME1, "domains", wild_dns])['rv'] == 0
    
    # --------- update ca ---------

    # test case: update CA URL
    def test_110_100(self):
        url = "http://localhost.com:9999"
        output = TestEnv.a2md(["update", self.NAME1, "ca", url])['jout']['output']
        assert len(output) == 1
        TestEnv.check_json_contains(output[0], {
            "name": self.NAME1,
            "domains": [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [],
            "ca": {
                "url": url,
                "proto": "ACME"
            },
            "state": TestEnv.MD_S_INCOMPLETE
        })

    # test case: update CA with invalid URL
    @pytest.mark.parametrize("invalid_url", [
        "no.schema/path", "http://white space/path", "http://bad.port:-1/path"
    ])
    def test_110_101(self, invalid_url):
        assert TestEnv.a2md(["update", self.NAME1, "ca", invalid_url])['rv'] == 1

    # test case: update ca protocol
    def test_110_102(self):
        md = TestEnv.a2md(["update", self.NAME1, "ca", TestEnv.ACME_URL, "FOO"])['jout']['output'][0]
        TestEnv.check_json_contains(md['ca'], {
            "url": TestEnv.ACME_URL,
            "proto": "FOO"
        })
        assert md['state'] == 1

    # test case: update account ID
    def test_110_200(self):
        acc_id = "test.account.id"
        output = TestEnv.a2md(["update", self.NAME1, "account", acc_id])['jout']['output']
        assert len(output) == 1
        TestEnv.check_json_contains(output[0], {
            "name": self.NAME1,
            "domains": [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [],
            "ca": {
                "account": acc_id,
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": TestEnv.MD_S_INCOMPLETE
        })

    # test case: remove account ID
    def test_110_201(self):
        assert TestEnv.a2md(["update", self.NAME1, "account", "test.account.id"])['rv'] == 0
        md = TestEnv.a2md(["update", self.NAME1, "account"])['jout']['output'][0]
        TestEnv.check_json_contains(md['ca'], {
            "url": TestEnv.ACME_URL,
            "proto": "ACME"
        })
        assert md['state'] == 1

    # test case: change existing account ID
    def test_110_202(self):
        assert TestEnv.a2md(["update", self.NAME1, "account", "test.account.id"])['rv'] == 0
        md = TestEnv.a2md(["update", self.NAME1, "account", "foo.test.com"])['jout']['output'][0]
        TestEnv.check_json_contains(md['ca'], {
            "account": "foo.test.com",
            "url": TestEnv.ACME_URL,
            "proto": "ACME"
        })
        assert md['state'] == 1

    # test case: ignore additional argument
    def test_110_203(self):
        md = TestEnv.a2md(["update", self.NAME1, "account", "test.account.id",
                           "test2.account.id"])['jout']['output'][0]
        TestEnv.check_json_contains(md['ca'], {
            "account": "test.account.id",
            "url": TestEnv.ACME_URL,
            "proto": "ACME"
        })
        assert md['state'] == 1

    # test case: add contact info
    def test_110_300(self):
        mail = "test@greenbytes.de"
        output = TestEnv.a2md(["update", self.NAME1, "contacts", mail])['jout']['output']
        assert len(output) == 1
        TestEnv.check_json_contains(output[0], {
            "name": self.NAME1,
            "domains": [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": ["mailto:" + mail],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME"
            },
            "state": TestEnv.MD_S_INCOMPLETE
        })

    # test case: add multiple contact info, preserve order
    def test_110_301(self):
        mail = ["xxx@greenbytes.de", "aaa@greenbytes.de"]
        md = TestEnv.a2md(["update", self.NAME1, "contacts"] + mail)['jout']['output'][0]
        assert md['contacts'] == ["mailto:" + mail[0], "mailto:" + mail[1]]
        assert md['state'] == 1

    # test case: must not remove contact info
    def test_110_302(self):
        assert TestEnv.a2md(["update", self.NAME1, "contacts", "test@greenbytes.de"])['rv'] == 0
        assert TestEnv.a2md(["update", self.NAME1, "contacts"])['rv'] == 1

    # test case: replace existing contact info
    def test_110_303(self):
        assert TestEnv.a2md(["update", self.NAME1, "contacts", "test@greenbytes.de"])['rv'] == 0
        md = TestEnv.a2md(["update", self.NAME1, "contacts", "xxx@greenbytes.de"])['jout']['output'][0]
        assert md['contacts'] == ["mailto:xxx@greenbytes.de"]
        assert md['state'] == 1

    # test case: use invalid mail address
    @pytest.mark.parametrize("invalid_mail", [
        "no.at.char", "with blank@test.com", "missing.host@", "@missing.localpart.de",
        "double..dot@test.com", "double@at@test.com"
    ])
    def test_110_304(self, invalid_mail):
        # SEI: Uhm, es ist nicht sinnvoll, eine komplette verification von
        # https://tools.ietf.org/html/rfc822 zu bauen?
        assert TestEnv.a2md(["update", self.NAME1, "contacts", invalid_mail])['rv'] == 1

    # test case: respect urls as given
    @pytest.mark.parametrize("url", [
        "mailto:test@greenbytes.de", "wrong://schema@test.com"])
    def test_110_305(self, url):
        md = TestEnv.a2md(["update", self.NAME1, "contacts", url])['jout']['output'][0]
        assert md['contacts'] == [url]
        assert md['state'] == 1

    # test case: add tos agreement
    def test_110_400(self):
        output = TestEnv.a2md(["update", self.NAME1, "agreement", TestEnv.ACME_TOS])['jout']['output']
        assert len(output) == 1
        TestEnv.check_json_contains(output[0], {
            "name": self.NAME1,
            "domains": [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [],
            "ca": {
                "url": TestEnv.ACME_URL,
                "proto": "ACME",
                "agreement": TestEnv.ACME_TOS
            },
            "state": TestEnv.MD_S_INCOMPLETE
        })

    # test case: update tos agreement
    def test_110_401(self):
        assert TestEnv.a2md(["update", self.NAME1, "agreement", TestEnv.ACME_TOS])['rv'] == 0
        md = TestEnv.a2md(["update", self.NAME1, "agreement", TestEnv.ACME_TOS2])['jout']['output'][0]
        TestEnv.check_json_contains(md['ca'], {
            "url": TestEnv.ACME_URL,
            "proto": "ACME",
            "agreement": TestEnv.ACME_TOS2
        })
        assert md['state'] == 1

    # test case: remove tos agreement
    def test_110_402(self):
        assert TestEnv.a2md(["update", self.NAME1, "agreement", TestEnv.ACME_TOS])['rv'] == 0
        md = TestEnv.a2md(["update", self.NAME1, "agreement"])['jout']['output'][0]
        TestEnv.check_json_contains(md['ca'], {
            "url": TestEnv.ACME_URL,
            "proto": "ACME"
        })
        assert md['state'] == 1

    # test case: ignore additional arguments
    def test_110_403(self):
        md = TestEnv.a2md(["update", self.NAME1, "agreement",
                           TestEnv.ACME_TOS, TestEnv.ACME_TOS2])['jout']['output'][0]
        TestEnv.check_json_contains(md['ca'], {
            "url": TestEnv.ACME_URL,
            "proto": "ACME",
            "agreement": TestEnv.ACME_TOS
        })
        assert md['state'] == 1

    # test case: update agreement with invalid URL
    @pytest.mark.parametrize("invalid_url", [
        "no.schema/path", "http://white space/path", "http://bad.port:-1/path"
    ])
    def test_110_404(self, invalid_url):
        assert TestEnv.a2md(["update", self.NAME1, "agreement", invalid_url])['rv'] == 1
