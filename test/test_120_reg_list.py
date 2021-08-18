# test mod_md acme terms-of-service handling

import os

from shutil import copyfile

import pytest


class TestRegAdd:

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env):
        env.clear_store()

    # test case: list empty store
    def test_120_000(self, env):
        assert env.a2md(["list"])['jout'] == env.EMPTY_JOUT

    # test case: list two managed domains
    def test_120_001(self, env):
        domains = [ 
            ["test120-001.com", "test120-001a.com", "test120-001b.com"],
            ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        ]
        for dns in domains:
            assert env.a2md(["add"] + dns)['rv'] == 0
        #
        # list all store content
        jout = env.a2md(["list"])['jout']
        assert len(jout['output']) == len(domains)
        domains.reverse()
        for i in range(0, len(jout['output'])):
            env.check_json_contains(jout['output'][i], {
                "name": domains[i][0],
                "domains": domains[i],
                "contacts": [],
                "ca": {
                    "url": env.ACME_URL,
                    "proto": "ACME"
                },
                "state": env.MD_S_INCOMPLETE
            })
        # list md by name
        for dns in ["test120-001.com", "greenbytes2.de"]:
            md = env.a2md(["list", dns])['jout']['output'][0]
            assert md['name'] == dns

    # test case: validate md state in store
    def test_120_002(self, env):
        # check: md without pkey/cert -> INCOMPLETE
        domain = "not-forbidden.org"
        assert env.a2md(["add", domain])['rv'] == 0
        assert env.a2md(["update", domain, "contacts", "admin@" + domain])['rv'] == 0
        assert env.a2md(["update", domain, "agreement", env.ACME_TOS])['rv'] == 0
        assert env.a2md(["list", domain])['jout']['output'][0]['state'] == env.MD_S_INCOMPLETE
        # check: valid pkey/cert -> COMPLETE
        copyfile(self._path_conf_ssl(env, "valid_pkey.pem"), env.store_domain_file(domain, 'privkey.pem'))
        copyfile(self._path_conf_ssl(env, "valid_cert.pem"), env.store_domain_file(domain, 'pubcert.pem'))
        assert env.a2md(["list", domain])['jout']['output'][0]['state'] == env.MD_S_COMPLETE
        # check: expired cert -> EXPIRED
        copyfile(self._path_conf_ssl(env, "expired_pkey.pem"), env.store_domain_file(domain, 'privkey.pem'))
        copyfile(self._path_conf_ssl(env, "expired_cert.pem"), env.store_domain_file(domain, 'pubcert.pem'))
        out = env.a2md(["list", domain])['jout']['output'][0]
        assert out['state'] == env.MD_S_INCOMPLETE
        assert out['renew'] is True

    # test case: broken cert file
    def test_120_003(self, env):
        domain = "not-forbidden.org"
        assert env.a2md(["add", domain])['rv'] == 0
        assert env.a2md(["update", domain, "contacts", "admin@" + domain])['rv'] == 0
        assert env.a2md(["update", domain, "agreement", env.ACME_TOS])['rv'] == 0
        # check: valid pkey/cert -> COMPLETE
        copyfile(self._path_conf_ssl(env, "valid_pkey.pem"), env.store_domain_file(domain, 'privkey.pem'))
        copyfile(self._path_conf_ssl(env, "valid_cert.pem"), env.store_domain_file(domain, 'pubcert.pem'))
        assert env.a2md(["list", domain])['jout']['output'][0]['state'] == env.MD_S_COMPLETE
        # check: replace cert by broken file -> ERROR
        copyfile(self._path_conf_ssl(env, "valid_cert.req"), env.store_domain_file(domain, 'pubcert.pem'))
        assert env.a2md(["list", domain])['jout']['output'][0]['state'] == env.MD_S_ERROR

    # REMOVED: we no longer verify private keys at startup and leave that to the
    #          user of the key, e.g. mod_ssl. It is the ultimate arbiter of this.
    # def test_120_004(self):
    # test case: broken private key file

    def _path_conf_ssl(self, env, name):
        return os.path.join(env.APACHE_SSL_DIR, name) 
