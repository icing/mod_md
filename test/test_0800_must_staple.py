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
from httplib import HTTPSConnection
from test_base import TestEnv
from test_base import HttpdConf
from test_base import CertUtil


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.APACHE_CONF_SRC = "data/test_auto"
    TestEnv.check_acme()
    TestEnv.clear_store()
    TestEnv.install_test_conf();
    assert TestEnv.apache_start() == 0
    

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestMustStaple:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.apache_err_reset();
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    #-----------------------------------------------------------------------------------------------
    # MD with default, e.g. not staple
    # 
    def test_800_001(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[])
        conf.install()

        # - restart (-> drive), check that md is in store
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert not cert1.get_must_staple()

    #-----------------------------------------------------------------------------------------------
    # MD that should explicitly not staple
    # 
    def test_800_002(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_must_staple( "off" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[])
        conf.install()

        # - restart (-> drive), check that md is in store
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert not cert1.get_must_staple()
        stat = TestEnv.get_ocsp_status(domain)
        assert stat['ocsp'] == "no response sent" 

    #-----------------------------------------------------------------------------------------------
    # MD that must staple and toggle off again
    # 
    def test_800_003(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_must_staple( "on" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[])
        conf.install()

        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert cert1.get_must_staple()

        # toggle MDMustStaple off, expect a cert that has it disabled
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_must_staple( "off" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[])
        conf.install()

        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert not cert1.get_must_staple()
    
        # toggle MDMustStaple on again, expect a cert that has it enabled
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_must_staple( "on" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[])
        conf.install()

        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert cert1.get_must_staple()

    #-----------------------------------------------------------------------------------------------
    # MD that must staple
    # 
    def test_800_004(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line("LogLevel ssl:trace2")
        conf.add_line("SSLUseStapling On")
        conf.add_line("SSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\"")
        conf.add_must_staple( "on" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[])
        conf.install()

        # - restart (-> drive), check that md is in store
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ] )
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        cert1 = CertUtil( TestEnv.store_domain_file(domain, 'pubcert.pem') )
        assert cert1.get_must_staple()
        # the mod_ssl OCSP Stapling implementation is configured, should report success
        stat = TestEnv.await_ocsp_status(domain)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"

