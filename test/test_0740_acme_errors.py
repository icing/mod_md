# test ACME error responses and their processing

from TestEnv import TestEnv
from TestHttpdConf import HttpdConf


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.initv2()
    TestEnv.APACHE_CONF_SRC = "data/test_auto"
    TestEnv.check_acme()
    TestEnv.clear_store()
    HttpdConf().install()
    assert TestEnv.apache_start() == 0
    

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestAcmeErrors:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # -----------------------------------------------------------------------------------------------
    # test case: MD with 2 names, one invalid
    #
    def test_740_000(self):
        domain = self.test_domain
        domains = [domain, "invalid!." + domain]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        md = TestEnv.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:rejectedIdentifier'
        assert md['renewal']['last']['detail'] == ("Error creating new order :: Cannot issue for "
                                                   "\"%s\": Domain name contains an invalid character"
                                                   % domains[1])

    # test case: MD with 3 names, 2 invalid
    #
    def test_740_001(self):
        domain = self.test_domain
        domains = [domain, "invalid1!." + domain, "invalid2!." + domain]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        md = TestEnv.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:rejectedIdentifier'
        # just check the beginning, reported name seems to vary sometimes
        assert md['renewal']['last']['detail'].startswith("Error creating new order :: Cannot issue for")
        assert md['renewal']['last']['subproblems']
        assert len(md['renewal']['last']['subproblems']) == 2
