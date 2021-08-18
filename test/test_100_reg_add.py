# test mod_md acme terms-of-service handling

import pytest


class TestRegAdd:

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env):
        env.purge_store()

    # test case: add a single dns managed domain
    def test_100_000(self, env):
        dns = "greenbytes.de"
        jout1 = env.a2md(["add", dns])['jout']
        env.check_json_contains(jout1['output'][0], {
            "name": dns,
            "domains": [dns],
            "contacts": [],
            "ca": {
                "url": env.ACME_URL,
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })
        assert env.a2md(["list"])['jout'] == jout1

    # test case: add > 1 dns managed domain
    def test_100_001(self, env):
        dns = ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        jout1 = env.a2md(["add"] + dns)['jout']
        env.check_json_contains(jout1['output'][0], {
            "name": dns[0],
            "domains": dns,
            "contacts": [],
            "ca": {
                "url": env.ACME_URL,
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })
        assert env.a2md(["list"])['jout'] == jout1

    # test case: add second managed domain
    def test_100_002(self, env):
        dns1 = ["test100-002.com", "test100-002a.com", "test100-002b.com"]
        env.a2md(["add"] + dns1)
        # add second managed domain
        dns2 = ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        jout = env.a2md(["add"] + dns2)['jout']
        # assert: output covers only changed md
        assert len(jout['output']) == 1
        env.check_json_contains(jout['output'][0], {
            "name": dns2[0],
            "domains": dns2,
            "contacts": [],
            "ca": {
                "url": env.ACME_URL,
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })
        assert len(env.a2md(["list"])['jout']['output']) == 2

    # test case: add existing domain 
    def test_100_003(self, env):
        dns = "greenbytes.de"
        assert env.a2md(["add", dns])['rv'] == 0
        assert env.a2md(["add", dns])['rv'] == 1

    # test case: add without CA URL
    def test_100_004(self, env):
        dns = "greenbytes.de"
        jout1 = env.run([env.A2MD, "-d", env.STORE_DIR, "-j", "add", dns])['jout']
        assert len(jout1['output']) == 1
        env.check_json_contains(jout1['output'][0], {
            "name": dns,
            "domains": [dns],
            "contacts": [],
            "ca": {
                "proto": "ACME"
            },
            "state": env.MD_S_INCOMPLETE
        })
        assert env.a2md(["list"])['jout'] == jout1

    # test case: add with invalid DNS
    @pytest.mark.parametrize("invalid_dns", [
        "tld", "white sp.ace", "invalid.*.wildcard.com", "k\xc3ller.idn.com"
    ])
    def test_100_005(self, env, invalid_dns):
        assert env.a2md(["add", invalid_dns])["rv"] == 1
        assert env.a2md(["add", "test-100.de", invalid_dns])["rv"] == 1

    # test case: add with invalid ACME URL
    @pytest.mark.parametrize("invalid_url", [
        "no.schema/path", "http://white space/path", "http://bad.port:-1/path"])
    def test_100_006(self, env, invalid_url):
        args = [env.A2MD, "-a", invalid_url, "-d", env.STORE_DIR, "-j"]
        dns = "greenbytes.de"
        args.extend(["add", dns])
        assert env.run(args)["rv"] == 1

    # test case: add overlapping dns names
    def test_100_007(self, env):
        assert env.a2md(["add", "test-100.com", "test-101.com"])['rv'] == 0
        # 1: alternate DNS exists as primary name
        assert env.a2md(["add", "greenbytes2.de", "test-100.com"])['rv'] == 1
        # 2: alternate DNS exists as alternate DNS
        assert env.a2md(["add", "greenbytes2.de", "test-101.com"])['rv'] == 1
        # 3: primary name exists as alternate DNS
        assert env.a2md(["add", "test-101.com"])['rv'] == 1

    # test case: add subdomains as separate managed domain
    def test_100_008(self, env):
        assert env.a2md(["add", "test-100.com"])['rv'] == 0
        assert env.a2md(["add", "sub.test-100.com"])['rv'] == 0

    # test case: add duplicate domain
    def test_100_009(self, env):
        dns1 = "test-100.com"
        dns2 = "test-101.com"
        jout = env.a2md(["add", dns1, dns2, dns1, dns2])['jout']
        # DNS is only listed once
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == [dns1, dns2]

    # test case: add pnuycode name
    def test_100_010(self, env):
        assert env.a2md(["add", "xn--kller-jua.punycode.de"])['rv'] == 0

    # test case: don't sort alternate names
    def test_100_011(self, env):
        dns = ["test-100.com", "test-xxx.com", "test-aaa.com"]
        jout = env.a2md(["add"] + dns)['jout']
        # DNS is only listed as specified
        assert len(jout['output']) == 1
        md = jout['output'][0]
        assert md['domains'] == dns

    # test case: add DNS wildcard
    @pytest.mark.parametrize("wild_dns", [
        "*.wildcard.com"
    ])
    def test_100_012(self, env, wild_dns):
        assert env.a2md(["add", wild_dns])['rv'] == 0
