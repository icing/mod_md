# test wildcard certifcates

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


class TestWildcard:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.initv2()
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard certificate with ACMEv1 
    #
    def test_720_000(self):
        domain = self.test_domain
        
        # switch to ACMEv1
        TestEnv.initv1()
        
        # generate config with DNS wildcard
        domains = [ domain, "*." + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domains )
        # await drive error as ACMEv1 does not accept DNS wildcards
        md = TestEnv.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:acme:error:malformed'

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard certificate with ACMEv2, no dns-01 supported
    #
    def test_720_001(self):
        domain = self.test_domain
        
        # generate config with DNS wildcard
        domains = [ domain, "*." + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domains )
        # await drive completion
        md = TestEnv.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'challenge-mismatch'


    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard certificate with ACMEv2, only dns-01 configured, invalid command path 
    #
    def test_720_002(self):
        dns01cmd = ("%s/dns01-not-found.py" % TestEnv.TESTROOT)

        domain = self.test_domain
        domains = [ domain, "*." + domain ]
        
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_ca_challenges( [ "dns-01" ] )
        conf.add_dns01_cmd( dns01cmd )
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domains )
        # await drive completion
        md = TestEnv.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'challenge-setup-failure'

    # variation, invalid cmd path, other challenges still get certificate for non-wildcard
    def test_720_002b(self):
        dns01cmd = ("%s/dns01-not-found.py" % TestEnv.TESTROOT)

        domain = self.test_domain
        domains = [ domain, "xxx." + domain ]
        
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_dns01_cmd( dns01cmd )
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domains )
        # await drive completion
        assert TestEnv.await_completion( [ domain ] )
        TestEnv.check_md_complete(domain)
        # check: SSL is running OK
        certA = TestEnv.get_cert(domain)
        altnames = certA.get_san_list()
        for domain in domains:
            assert domain in altnames

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard certificate with ACMEv2, only dns-01 configured, invalid command option 
    #
    def test_720_003(self):
        dns01cmd = ("%s/dns01.py fail" % TestEnv.TESTROOT)

        domain = self.test_domain
        domains = [ domain, "*." + domain ]
        
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_ca_challenges( [ "dns-01" ] )
        conf.add_dns01_cmd( dns01cmd )
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domains )
        # await drive completion
        md = TestEnv.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'challenge-setup-failure'

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard name certificate with ACMEv2, only dns-01 configured 
    #
    def test_720_004(self):
        dns01cmd = ("%s/dns01.py" % TestEnv.TESTROOT)

        domain = self.test_domain
        domains = [ domain, "*." + domain ]
        
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_ca_challenges( [ "dns-01" ] )
        conf.add_dns01_cmd( dns01cmd )
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domains )
        # await drive completion
        assert TestEnv.await_completion( [ domain ] )
        TestEnv.check_md_complete(domain)
        # check: SSL is running OK
        certA = TestEnv.get_cert(domain)
        altnames = certA.get_san_list()
        for domain in domains:
            assert domain in altnames

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard name and 2nd normal vhost, not overlapping
    #
    def test_720_005(self):
        dns01cmd = ("%s/dns01.py" % TestEnv.TESTROOT)

        domain = self.test_domain
        domain2 = "www.x" + domain
        domains = [ domain, "*." + domain, domain2 ]
        
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_ca_challenges( [ "dns-01" ] )
        conf.add_dns01_cmd( dns01cmd )
        conf.add_md( domains )
        conf.add_vhost(domain2)
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domains )
        # await drive completion
        assert TestEnv.await_completion( [ domain ] )
        TestEnv.check_md_complete(domain)
        # check: SSL is running OK
        certA = TestEnv.get_cert(domain)
        altnames = certA.get_san_list()
        for domain in domains:
            assert domain in altnames

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard name and 2nd normal vhost, overlapping
    #
    def test_720_006(self):
        dns01cmd = ("%s/dns01.py" % TestEnv.TESTROOT)

        domain = self.test_domain
        dwild = "*." + domain
        domain2 = "www." + domain
        domains = [ domain, dwild, domain2 ]
        
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_ca_challenges( [ "dns-01" ] )
        conf.add_dns01_cmd( dns01cmd )
        conf.add_md( domains )
        conf.add_vhost(domain2)
        conf.add_vhost([ domain, dwild ])
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domains )
        # await drive completion
        assert TestEnv.await_completion( [ domain ] )
        TestEnv.check_md_complete(domain)
        # check: SSL is running OK
        certA = TestEnv.get_cert(domain)
        altnames = certA.get_san_list()
        for domain in [ domain, dwild ]:
            assert domain in altnames


