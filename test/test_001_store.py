# test mod_md acme terms-of-service handling

import re

import pytest

from md_env import MDTestEnv


def md_name(md):
    return md['name']


class TestStore:

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env):
        env.purge_store()
 
    # verify expected binary version
    def test_001_001(self, env: MDTestEnv):
        run = env.run([env.A2MD, "-V"])
        m = re.match("version: %s(-git)?$" % env.A2MD_VERSION, run['stdout'])
        assert m

    # verify that store is clean
    def test_001_002(self, env: MDTestEnv):
        run = env.run(["find", env.STORE_DIR])
        assert re.match(env.STORE_DIR, run['stdout'])

    # test case: add a single dns managed domain
    def test_001_100(self, env: MDTestEnv):
        dns = "greenbytes.de"
        env.check_json_contains(
            env.a2md(["store", "add", dns])['jout']['output'][0],
            {
                "name": dns,
                "domains": [dns],
                "contacts": [],
                "ca": {
                    "url": env.ACME_URL,
                    "proto": "ACME"
                },
                "state": 0
            })

    # test case: add > 1 dns managed domain
    def test_001_101(self, env: MDTestEnv):
        dns = ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        env.check_json_contains(
            env.a2md(["store", "add"] + dns)['jout']['output'][0],
            {
                "name": dns[0],
                "domains": dns,
                "contacts": [],
                "ca": {
                    "url": env.ACME_URL,
                    "proto": "ACME"
                },
                "state": 0
            })

    # test case: add second managed domain
    def test_001_102(self, env: MDTestEnv):
        dns1 = ["test000-102.com", "test000-102a.com", "test000-102b.com"]
        assert env.a2md(["store", "add"] + dns1)['rv'] == 0
        #
        # add second managed domain
        dns2 = ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        jout = env.a2md(["store", "add"] + dns2)['jout']
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
            "state": 0
        })

    # test case: add existing domain 
    def test_001_103(self, env: MDTestEnv):
        dns = "greenbytes.de"
        assert env.a2md(["store", "add", dns])['rv'] == 0
        # add same domain again
        assert env.a2md(["store", "add", dns])['rv'] == 1

    # test case: add without CA URL
    def test_001_104(self, env: MDTestEnv):
        dns = "greenbytes.de"
        args = [env.A2MD, "-d", env.STORE_DIR, "-j", "store", "add", dns]
        jout = env.run(args)['jout']
        assert len(jout['output']) == 1
        env.check_json_contains(jout['output'][0], {
            "name": dns,
            "domains": [dns],
            "contacts": [],
            "ca": {
                "proto": "ACME"
            },
            "state": 0
        })

    # test case: list empty store
    def test_001_200(self, env: MDTestEnv):
        assert env.a2md(["store", "list"])['jout'] == env.EMPTY_JOUT

    # test case: list two managed domains
    def test_001_201(self, env: MDTestEnv):
        domains = [ 
            ["test000-201.com", "test000-201a.com", "test000-201b.com"],
            ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        ]
        for dns in domains:
            assert env.a2md(["store", "add"] + dns)['rv'] == 0
        #
        # list all store content
        jout = env.a2md(["store", "list"])['jout']
        assert len(jout['output']) == len(domains)
        domains.reverse()
        jout['output'] = sorted(jout['output'], key=md_name)
        for i in range(0, len(jout['output'])):
            env.check_json_contains(jout['output'][i], {
                "name": domains[i][0],
                "domains": domains[i],
                "contacts": [],
                "ca": {
                    "url": env.ACME_URL,
                    "proto": "ACME"
                },
                "state": 0
            })

    # test case: remove managed domain
    def test_001_300(self, env: MDTestEnv):
        dns = "test000-300.com"
        assert env.a2md(["store", "add", dns])['rv'] == 0
        assert env.a2md(["store", "remove", dns])['jout'] == env.EMPTY_JOUT
        assert env.a2md(["store", "list"])['jout'] == env.EMPTY_JOUT

    # test case: remove from list of managed domains 
    def test_001_301(self, env: MDTestEnv):
        dns1 = ["test000-301.com", "test000-301a.com", "test000-301b.com"]
        assert env.a2md(["store", "add"] + dns1)['rv'] == 0
        #
        dns2 = ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        jout1 = env.a2md(["store", "add"] + dns2)['jout']
        # remove managed domain
        assert env.a2md(["store", "remove", "test000-301.com"])['jout'] == env.EMPTY_JOUT
        # list store content
        assert env.a2md(["store", "list"])['jout'] == jout1

    # test case: remove nonexisting managed domain
    def test_001_302(self, env: MDTestEnv):
        dns1 = "test000-302.com"
        run = env.a2md(["store", "remove", dns1])
        assert run['rv'] == 1
        assert run['jout'] == { 
            'status': 2, 'description': 'No such file or directory', 'output': []
        }

    # test case: force remove nonexisting managed domain
    def test_001_303(self, env: MDTestEnv):
        dns1 = "test000-303.com"
        assert env.a2md(["store", "remove", "-f", dns1])['jout'] == env.EMPTY_JOUT

    # test case: null change
    def test_001_400(self, env: MDTestEnv):
        dns = "test000-400.com"
        run1 = env.a2md(["store", "add", dns])
        assert env.a2md(["store", "update", dns])['jout'] == run1['jout']

    # test case: add dns to managed domain
    def test_001_401(self, env: MDTestEnv):
        dns1 = "test000-401.com"
        env.a2md(["store", "add", dns1])
        dns2 = "test-101.com"
        args = ["store", "update", dns1, "domains", dns1, dns2]
        assert env.a2md(args)['jout']['output'][0]['domains'] == [dns1, dns2]

    # test case: change CA URL
    def test_001_402(self, env: MDTestEnv):
        dns = "test000-402.com"
        args = ["store", "add", dns]
        assert env.a2md(args)['jout']['output'][0]['ca']['url'] == env.ACME_URL
        nurl = "https://foo.com/"
        args = [env.A2MD, "-a", nurl, "-d", env.STORE_DIR, "-j", "store", "update", dns]
        assert env.run(args)['jout']['output'][0]['ca']['url'] == nurl

    # test case: update nonexisting managed domain
    def test_001_403(self, env: MDTestEnv):
        dns = "test000-403.com"
        assert env.a2md(["store", "update", dns])['rv'] == 1

    # test case: update domains, throw away md name
    def test_001_404(self, env: MDTestEnv):
        dns1 = "test000-404.com"
        dns2 = "greenbytes.com"
        args = ["store", "add", dns1]
        assert env.a2md(args)['jout']['output'][0]['domains'] == [dns1]
        # override domains list
        args = ["store", "update", dns1, "domains", dns2]
        assert env.a2md(args)['jout']['output'][0]['domains'] == [dns2]

    # test case: update domains with empty dns list
    def test_001_405(self, env: MDTestEnv):
        dns1 = "test000-405.com"
        assert env.a2md(["store", "add", dns1])['rv'] == 0
        assert env.a2md(["store", "update", dns1, "domains"])['rv'] == 1
