# tests with elliptic curve keys and certificates

import pytest

from TestEnv import TestEnv
from TestHttpdConf import HttpdConf


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.APACHE_CONF_SRC = "data/test_auto"
    TestEnv.check_acme()
    TestEnv.clear_store()
    HttpdConf().install()
    assert TestEnv.apache_start() == 0


def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestAutov2:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.httpd_error_log_clear()
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def set_get_pkeys(self, domain, pkeys, conf=None):
        domains = [domain]
        if conf is None:
            conf = HttpdConf()
            conf.add_admin("admin@" + domain)
            conf.add_line("MDPrivateKeys {0}".format(" ".join([p['spec'] for p in pkeys])))
            conf.add_md(domains)
            conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([domain])

    def check_pkeys(self, domain, pkeys):
        # check that files for all types have been created
        for p in [p for p in pkeys if len(p['spec'])]:
            TestEnv.check_md_complete(domain, p['spec'])
        # check that openssl client sees the cert with given keylength for cipher
        TestEnv.verify_cert_key_lenghts(domain, pkeys)
    
    def set_get_check_pkeys(self, domain, pkeys, conf=None):
        self.set_get_pkeys(domain, pkeys, conf=conf)
        self.check_pkeys(domain, pkeys)
        
    # one EC key, no RSA
    def test_810_001(self):
        domain = self.test_domain
        self.set_get_check_pkeys(domain, [
            {'spec': "secp256r1", 'ciphers': "ECDSA", 'keylen': 256},
            {'spec': "", 'ciphers': "RSA", 'keylen': 0},
        ])

    # set EC key type override on MD and get certificate
    def test_810_002(self):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain]
        conf = HttpdConf()
        conf.add_admin("admin@" + domain)
        conf.add_line("MDPrivateKeys secp256r1")
        conf.start_md(domains)
        conf.add_line("    MDPrivateKeys secp384r1")
        conf.end_md()
        conf.add_vhost(domains)
        self.set_get_check_pkeys(domain, [ 
            {'spec': "secp384r1", 'ciphers': "ECDSA", 'keylen': 384},
            {'spec': "", 'ciphers': "RSA", 'keylen': 0},
        ])

    # set two key spec, ec before rsa
    def test_810_003a(self):
        domain = self.test_domain
        self.set_get_check_pkeys(domain, [ 
            {'spec': "P-256", 'ciphers': "ECDSA", 'keylen': 256},
            {'spec': "RSA 3072", 'ciphers': "RSA", 'keylen': 3072},
        ])

    # set two key spec, rsa before ec
    def test_810_003b(self):
        domain = self.test_domain
        self.set_get_check_pkeys(domain, [ 
            {'spec': "RSA 3072", 'ciphers': "RSA", 'keylen': 3072},
            {'spec': "secp384r1", 'ciphers': "ECDSA", 'keylen': 384},
        ])

    # use a curve unsupported by LE
    def test_810_004(self):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain]
        conf = HttpdConf()
        conf.add_admin("admin@" + domain)
        conf.add_line("MDPrivateKeys secp192r1")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        md = TestEnv.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:malformed'

    # set three key specs
    def test_810_005(self):
        domain = self.test_domain
        self.set_get_check_pkeys(domain, [ 
            {'spec': "secp256r1", 'ciphers': "ECDSA", 'keylen': 384},  # we will see the cert from 3
            {'spec': "RSA 4096", 'ciphers': "RSA", 'keylen': 4096},
            {'spec': "P-384", 'ciphers': "ECDSA", 'keylen': 384},
        ])

    # disabled completely, since LE does not support that key type
    # X25529 key type which has some special quirks
    #@pytest.mark.skip(reason="this is not working yet.")
    #def test_810_010(self):
    #    domain = self.test_domain
    #    self.set_get_check_pkeys(domain, [
    #        {'spec': "x25519", 'ciphers': "ECDSA", 'keylen': 384},
    #    ])
