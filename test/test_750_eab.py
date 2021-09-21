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
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'
