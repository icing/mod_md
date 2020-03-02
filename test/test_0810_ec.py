# tests with elliptic curve keys and certificates

import json
import os
import pytest
import re
import socket
import ssl
import sys
import time

from datetime import datetime
from TestEnv import TestEnv
from TestHttpdConf import HttpdConf
from TestCertUtil import CertUtil


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.initv2()
    TestEnv.APACHE_CONF_SRC = "data/test_auto"
    TestEnv.check_acme()
    TestEnv.clear_store()
    HttpdConf().install();
    assert TestEnv.apache_start() == 0

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0

class TestAutov2:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.httpd_error_log_clear();
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # set EC key type globally and get certificate
    def test_810_001(self):
        domain = self.test_domain
        # generate config with one MD
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line("MDPrivateKeys secp256r1")
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        TestEnv.check_md_complete(domain, 'secp256r1')
        stat = TestEnv.get_md_status(domain)
        cert = TestEnv.get_cert(domain)
        assert cert.get_key_length() == 256

    # set EC key type on MD and get certificate
    def test_810_002(self):
        domain = self.test_domain
        # generate config with one MD
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line("MDPrivateKeys secp256r1")
        conf.start_md( domains )
        conf.add_line("    MDPrivateKeys secp384r1")
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        TestEnv.check_md_complete(domain, 'secp384r1')
        stat = TestEnv.get_md_status(domain)
        cert = TestEnv.get_cert(domain)
        assert cert.get_key_length() == 384

    # set two key spec, ec before rsa
    def test_810_003a(self):
        domain = self.test_domain
        # generate config with one MD
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line("MDPrivateKeys secp256r1 RSA 3072")
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        TestEnv.check_md_complete(domain, 'secp256r1')
        stat = TestEnv.get_md_status(domain)
        cert = TestEnv.get_cert(domain, ciphers="ECDHE-ECDSA-AES256-GCM-SHA384")
        assert cert.get_key_length() == 256

    # set two key spec, rsa before ec
    def test_810_003b(self):
        domain = self.test_domain
        # generate config with one MD
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line("MDPrivateKeys RSA 3072 secp384r1")
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        TestEnv.check_md_complete(domain)
        stat = TestEnv.get_md_status(domain)
        # TODO: find out how to force usage of hte RSA certificate, so we see the 3072 key length
        cert = TestEnv.get_cert(domain, ciphers="DHE-RSA-AES256-SHA256")
        assert cert.get_key_length() == 384

    # use a curve unsupported by LE
    def test_810_004(self):
        domain = self.test_domain
        # generate config with one MD
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line("MDPrivateKeys secp192r1")
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        md = TestEnv.await_error( domain )
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:malformed'

    # set three key specs
    def test_810_005(self):
        domain = self.test_domain
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line("MDPrivateKeys secp256r1 RSA 4096 P-384")
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        TestEnv.check_md_complete(domain, 'secp256r1')
        TestEnv.check_md_complete(domain, 'RSA')
        TestEnv.check_md_complete(domain, 'P-384')
        stat = TestEnv.get_md_status(domain)
        cert = TestEnv.get_cert(domain)
        assert cert.get_key_length() == 384
