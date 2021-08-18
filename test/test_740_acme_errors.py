# test ACME error responses and their processing
import pytest

from md_conf import HttpdConf


class TestAcmeErrors:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.APACHE_CONF_SRC = "data/test_auto"
        env.check_acme()
        env.clear_store()
        HttpdConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    # -----------------------------------------------------------------------------------------------
    # test case: MD with 2 names, one invalid
    #
    def test_740_000(self, env):
        domain = self.test_domain
        domains = [domain, "invalid!." + domain]
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        if env.ACME_SERVER == 'pebble':
            assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:malformed'
            assert md['renewal']['last']['detail'] == \
                   "Order included DNS identifier with a value containing an illegal character: '!'"
        else:
            assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:rejectedIdentifier'
            assert md['renewal']['last']['detail'] == (
                    "Error creating new order :: Cannot issue for "
                    "\"%s\": Domain name contains an invalid character" % domains[1])

    # test case: MD with 3 names, 2 invalid
    #
    def test_740_001(self, env):
        domain = self.test_domain
        domains = [domain, "invalid1!." + domain, "invalid2!." + domain]
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        if env.ACME_SERVER == 'pebble':
            assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:malformed'
            assert md['renewal']['last']['detail'].startswith(
                "Order included DNS identifier with a value containing an illegal character")
        else:
            assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:rejectedIdentifier'
            assert md['renewal']['last']['detail'].startswith(
                "Error creating new order :: Cannot issue for")
            assert md['renewal']['last']['subproblems']
            assert len(md['renewal']['last']['subproblems']) == 2
