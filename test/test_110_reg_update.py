# test mod_md acme terms-of-service handling

import pytest


class TestRegUpdate:

    NAME1 = "greenbytes2.de"
    NAME2 = "test-100.com"

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env):
        env.clear_store()
        # add managed domains
        domains = [ 
            [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            [self.NAME2, "test-101.com", "test-102.com"]
        ]
        for dns in domains:
            env.a2md(["-a", env.ACME_URL, "add"] + dns)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # test case: update domains
    def test_110_000(self, env):
        dns = ["foo.de", "bar.de"]
        output1 = env.a2md(["-vvvv", "update", self.NAME1, "domains"] + dns)['jout']['output']
        assert len(output1) == 1
        env.check_json_contains(output1[0], {
            "name": self.NAME1,
            "domains": dns,
            "contacts": [],
            "ca": {
                "url": env.ACME_URL,
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })
        assert env.a2md(["list"])['jout']['output'][0] == output1[0]

    # test case: remove all domains
    def test_110_001(self, env):
        assert env.a2md(["update", self.NAME1, "domains"])['rv'] == 1

    # test case: update domains with invalid DNS
    @pytest.mark.parametrize("invalid_dns", [
        "tld", "white sp.ace", "invalid.*.wildcard.com", "k\xc3ller.idn.com"
    ])
    def test_110_002(self, env, invalid_dns):
        assert env.a2md(["update", self.NAME1, "domains", invalid_dns])['rv'] == 1

    # test case: update domains with overlapping DNS list
    def test_110_003(self, env):
        dns = [self.NAME1, self.NAME2]
        assert env.a2md(["update", self.NAME1, "domains"] + dns)['rv'] == 1

    # test case: update with subdomains
    def test_110_004(self, env):
        dns = ["test-foo.com", "sub.test-foo.com"]
        md = env.a2md(["update", self.NAME1, "domains"] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    # test case: update domains with duplicates
    def test_110_005(self, env):
        dns = [self.NAME1, self.NAME1, self.NAME1]
        md = env.a2md(["update", self.NAME1, "domains"] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == [self.NAME1]

    # test case: remove domains with punycode
    def test_110_006(self, env):
        dns = [self.NAME1, "xn--kller-jua.punycode.de"]
        md = env.a2md(["update", self.NAME1, "domains"] + dns)['jout']['output'][0]
        assert md['name'] == self.NAME1
        assert md['domains'] == dns

    # test case: update non-existing managed domain
    def test_110_007(self, env):
        assert env.a2md(["update", "test-foo.com", "domains", "test-foo.com"])['rv'] == 1

    # test case: update domains with DNS wildcard
    @pytest.mark.parametrize("wild_dns", [
        "*.wildcard.com"
    ])
    def test_110_008(self, env, wild_dns):
        assert env.a2md(["update", self.NAME1, "domains", wild_dns])['rv'] == 0
    
    # --------- update ca ---------

    # test case: update CA URL
    def test_110_100(self, env):
        url = "http://localhost.com:9999"
        output = env.a2md(["update", self.NAME1, "ca", url])['jout']['output']
        assert len(output) == 1
        env.check_json_contains(output[0], {
            "name": self.NAME1,
            "domains": [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [],
            "ca": {
                "url": url,
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })

    # test case: update CA with invalid URL
    @pytest.mark.parametrize("invalid_url", [
        "no.schema/path", "http://white space/path", "http://bad.port:-1/path"
    ])
    def test_110_101(self, env, invalid_url):
        assert env.a2md(["update", self.NAME1, "ca", invalid_url])['rv'] == 1

    # test case: update ca protocol
    def test_110_102(self, env):
        md = env.a2md(["update", self.NAME1, "ca", env.ACME_URL, "FOO"])['jout']['output'][0]
        env.check_json_contains(md['ca'], {
            "url": env.ACME_URL,
            "proto": "FOO"
        })
        assert md['state'] == 1

    # test case: update account ID
    def test_110_200(self, env):
        acc_id = "test.account.id"
        output = env.a2md(["update", self.NAME1, "account", acc_id])['jout']['output']
        assert len(output) == 1
        env.check_json_contains(output[0], {
            "name": self.NAME1,
            "domains": [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [],
            "ca": {
                "account": acc_id,
                "url": env.ACME_URL,
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })

    # test case: remove account ID
    def test_110_201(self, env):
        assert env.a2md(["update", self.NAME1, "account", "test.account.id"])['rv'] == 0
        md = env.a2md(["update", self.NAME1, "account"])['jout']['output'][0]
        env.check_json_contains(md['ca'], {
            "url": env.ACME_URL,
            "proto": "ACME"
        })
        assert md['state'] == 1

    # test case: change existing account ID
    def test_110_202(self, env):
        assert env.a2md(["update", self.NAME1, "account", "test.account.id"])['rv'] == 0
        md = env.a2md(["update", self.NAME1, "account", "foo.test.com"])['jout']['output'][0]
        env.check_json_contains(md['ca'], {
            "account": "foo.test.com",
            "url": env.ACME_URL,
            "proto": "ACME"
        })
        assert md['state'] == 1

    # test case: ignore additional argument
    def test_110_203(self, env):
        md = env.a2md(["update", self.NAME1, "account", "test.account.id",
                       "test2.account.id"])['jout']['output'][0]
        env.check_json_contains(md['ca'], {
            "account": "test.account.id",
            "url": env.ACME_URL,
            "proto": "ACME"
        })
        assert md['state'] == 1

    # test case: add contact info
    def test_110_300(self, env):
        mail = "test@greenbytes.de"
        output = env.a2md(["update", self.NAME1, "contacts", mail])['jout']['output']
        assert len(output) == 1
        env.check_json_contains(output[0], {
            "name": self.NAME1,
            "domains": [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": ["mailto:" + mail],
            "ca": {
                "url": env.ACME_URL,
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })

    # test case: add multiple contact info, preserve order
    def test_110_301(self, env):
        mail = ["xxx@greenbytes.de", "aaa@greenbytes.de"]
        md = env.a2md(["update", self.NAME1, "contacts"] + mail)['jout']['output'][0]
        assert md['contacts'] == ["mailto:" + mail[0], "mailto:" + mail[1]]
        assert md['state'] == 1

    # test case: must not remove contact info
    def test_110_302(self, env):
        assert env.a2md(["update", self.NAME1, "contacts", "test@greenbytes.de"])['rv'] == 0
        assert env.a2md(["update", self.NAME1, "contacts"])['rv'] == 1

    # test case: replace existing contact info
    def test_110_303(self, env):
        assert env.a2md(["update", self.NAME1, "contacts", "test@greenbytes.de"])['rv'] == 0
        md = env.a2md(["update", self.NAME1, "contacts", "xxx@greenbytes.de"])['jout']['output'][0]
        assert md['contacts'] == ["mailto:xxx@greenbytes.de"]
        assert md['state'] == 1

    # test case: use invalid mail address
    @pytest.mark.parametrize("invalid_mail", [
        "no.at.char", "with blank@test.com", "missing.host@", "@missing.localpart.de",
        "double..dot@test.com", "double@at@test.com"
    ])
    def test_110_304(self, env, invalid_mail):
        # SEI: Uhm, es ist nicht sinnvoll, eine komplette verification von
        # https://tools.ietf.org/html/rfc822 zu bauen?
        assert env.a2md(["update", self.NAME1, "contacts", invalid_mail])['rv'] == 1

    # test case: respect urls as given
    @pytest.mark.parametrize("url", [
        "mailto:test@greenbytes.de", "wrong://schema@test.com"])
    def test_110_305(self, env, url):
        md = env.a2md(["update", self.NAME1, "contacts", url])['jout']['output'][0]
        assert md['contacts'] == [url]
        assert md['state'] == 1

    # test case: add tos agreement
    def test_110_400(self, env):
        output = env.a2md(["update", self.NAME1, "agreement", env.ACME_TOS])['jout']['output']
        assert len(output) == 1
        env.check_json_contains(output[0], {
            "name": self.NAME1,
            "domains": [self.NAME1, "www.greenbytes2.de", "mail.greenbytes2.de"],
            "contacts": [],
            "ca": {
                "url": env.ACME_URL,
                "proto": "ACME",
                "agreement": env.ACME_TOS
            },
            "state": env.MD_S_INCOMPLETE
        })

    # test case: remove tos agreement
    def test_110_402(self, env):
        assert env.a2md(["update", self.NAME1, "agreement", env.ACME_TOS])['rv'] == 0
        md = env.a2md(["update", self.NAME1, "agreement"])['jout']['output'][0]
        env.check_json_contains(md['ca'], {
            "url": env.ACME_URL,
            "proto": "ACME"
        })
        assert md['state'] == 1

    # test case: ignore additional arguments
    def test_110_403(self, env):
        md = env.a2md(["update", self.NAME1, "agreement",
                       env.ACME_TOS, "http://invalid.tos/"])['jout']['output'][0]
        env.check_json_contains(md['ca'], {
            "url": env.ACME_URL,
            "proto": "ACME",
            "agreement": env.ACME_TOS
        })
        assert md['state'] == 1

    # test case: update agreement with invalid URL
    @pytest.mark.parametrize("invalid_url", [
        "no.schema/path", "http://white space/path", "http://bad.port:-1/path"
    ])
    def test_110_404(self, env, invalid_url):
        assert env.a2md(["update", self.NAME1, "agreement", invalid_url])['rv'] == 1
