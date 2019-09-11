# test mod_md must-staple support

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


class TestMustStaple:

    @classmethod
    def setup_class(cls):
        print("setup_class:%s" % cls.__name__)
        TestEnv.init()
        TestEnv.clear_store()
        TestEnv.check_acme()
        cls.domain = TestEnv.get_class_domain(cls)
        cls.configure_httpd(cls.domain)
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ cls.domain ] )

    @classmethod
    def teardown_class(cls):
        print("teardown_class:%s" % cls.__name__)
        assert TestEnv.apache_stop() == 0

    @classmethod
    def configure_httpd(cls, domain, add_lines=""):
        cls.domain = domain 
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line( add_lines )
        conf.add_md([ domain ])
        conf.add_vhost(domain)
        conf.install()
        return domain
    
    # MD with default, e.g. not staple
    def test_800_001(self):
        domain = TestMustStaple.domain
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert not cert1.get_must_staple()

    # MD that should explicitly not staple
    def test_800_002(self):
        domain = TestMustStaple.domain
        TestMustStaple.configure_httpd(domain, "MDMustStaple off")
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert not cert1.get_must_staple()
        stat = TestEnv.get_ocsp_status(domain)
        assert stat['ocsp'] == "no response sent" 

    # MD that must staple and toggle off again
    def test_800_003(self):
        domain = TestMustStaple.domain
        TestMustStaple.configure_httpd(domain, "MDMustStaple on")
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert cert1.get_must_staple()
        domain = TestMustStaple.configure_httpd(domain, "MDMustStaple off")
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert not cert1.get_must_staple()

    # MD that must staple
    def test_800_004(self):
        domain = TestMustStaple.domain
        # mod_ssl stapling is off, expect no stapling
        stat = TestEnv.get_ocsp_status(domain)
        assert stat['ocsp'] == "no response sent" 
        # turn mod_ssl stapling on, expect an answer
        domain = TestMustStaple.configure_httpd(domain, """
            LogLevel ssl:trace2
            SSLUseStapling On
            SSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\"
            """)
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_ocsp_status(domain)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
