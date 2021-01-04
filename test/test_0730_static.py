# test MDs with static certificates

import os

from TestEnv import TestEnv
from TestHttpdConf import HttpdConf


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.APACHE_CONF_SRC = "data/test_auto"
    TestEnv.check_acme()
    TestEnv.clear_store()
    HttpdConf().install()
    

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestStatus:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_730_001(self):
        # MD with static cert files, will not be driven
        domain = self.test_domain
        domains = [domain, 'www.%s' % domain]
        testpath = os.path.join(TestEnv.GEN_DIR, 'test_920_001')
        # cert that is only 10 more days valid
        TestEnv.create_self_signed_cert(domains, {"notBefore": -80, "notAfter": 10},
                                        serial=730001, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.start_md(domains)
        conf.add_line("MDCertificateFile %s" % cert_file)
        conf.add_line("MDCertificateKeyFile %s" % pkey_file)
        conf.end_md()
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        
        # check if the domain uses it, it appears in our stats and renewal is off
        cert = TestEnv.get_cert(domain)
        assert cert.same_serial_as(730001)
        stat = TestEnv.get_md_status(domain)
        assert stat
        assert 'cert' in stat
        assert stat['renew'] is True
        assert 'renewal' not in stat

    def test_730_002(self):
        # MD with static cert files, force driving
        domain = self.test_domain
        domains = [domain, 'www.%s' % domain]
        testpath = os.path.join(TestEnv.GEN_DIR, 'test_920_001')
        # cert that is only 10 more days valid
        TestEnv.create_self_signed_cert(domains, {"notBefore": -80, "notAfter": 10},
                                        serial=730001, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.start_md(domains)
        conf.add_line("MDCertificateFile %s" % cert_file)
        conf.add_line("MDCertificateKeyFile %s" % pkey_file)
        conf.add_line("MDRenewMode always")
        conf.end_md()
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        
        # check if the domain uses it, it appears in our stats and renewal is off
        cert = TestEnv.get_cert(domain)
        assert cert.same_serial_as(730001)
        stat = TestEnv.get_md_status(domain)
        assert stat
        assert 'cert' in stat
        assert stat['renew'] is True
        assert TestEnv.await_renewal(domains)

    def test_730_003(self):
        # just configuring one file will not work
        domain = self.test_domain
        domains = [domain, 'www.%s' % domain]
        testpath = os.path.join(TestEnv.GEN_DIR, 'test_920_001')
        # cert that is only 10 more days valid
        TestEnv.create_self_signed_cert(domains, {"notBefore": -80, "notAfter": 10},
                                        serial=730001, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.start_md(domains)
        conf.add_line("MDCertificateFile %s" % cert_file)
        conf.end_md()
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_fail() == 0
        
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.start_md(domains)
        conf.add_line("MDCertificateKeyFile %s" % pkey_file)
        conf.end_md()
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_fail() == 0
