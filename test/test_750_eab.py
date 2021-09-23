import os

import pytest

from md_conf import HttpdConf
from md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_eab(),
                    reason="ACME test server does not support External Account Binding")
class TestEab:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='eab')
        env.check_acme()
        env.clear_store()
        HttpdConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    def test_750_001(self, env):
        # md without EAB configured
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf(env)
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'

    def test_750_002(self, env):
        # md with known EAB KID and non base64 hmac key configured
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf(env)
        conf.add("MDExternalAccountBinding kid-1 äöüß")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'apache:eab-hmac-invalid'

    def test_750_003(self, env):
        # md with empty EAB KID configured
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf(env)
        conf.add("MDExternalAccountBinding \" \" bm90IGEgdmFsaWQgaG1hYwo=")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:unauthorized'

    def test_750_004(self, env):
        # md with unknown EAB KID configured
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf(env)
        conf.add("MDExternalAccountBinding key-x bm90IGEgdmFsaWQgaG1hYwo=")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:unauthorized'

    def test_750_005(self, env):
        # md with known EAB KID but wrong HMAC configured
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf(env)
        conf.add("MDExternalAccountBinding kid-1 bm90IGEgdmFsaWQgaG1hYwo=")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:unauthorized'

    def test_750_010(self, env):
        # md with correct EAB configured
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf(env)
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
