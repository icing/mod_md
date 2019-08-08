# test migration from ACMEv1 to ACMEv2

import json
import os
import pytest
import re
import socket
import ssl
import sys
import time

from datetime import datetime
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


class TestMigration:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.httpd_error_log_clear();
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    #-----------------------------------------------------------------------------------------------
    # create a MD with ACMEv1, let it get a cert, change config to ACMEv2
    # 
    def test_710_001(self):
        domain = self.test_domain

        # use ACMEv1 initially
        TestEnv.set_acme('acmev1')
        
        # generate config with one MD, restart, gets cert
        domains = [ domain, "www." + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        TestEnv.check_md_complete(domain)
        cert1 = TestEnv.get_cert(domain)
        assert domain in cert1.get_san_list()
 
        # use ACMEv2 now for everything
        TestEnv.set_acme('acmev2')

        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()
        # restart, gets cert, should still be the same cert as it remains valid
        assert TestEnv.apache_restart() == 0
        status = TestEnv.get_certificate_status( domain )
        assert status['serial'] == cert1.get_serial() 
        
        # change the MD so that we need a new cert
        domains = [ domain, "www." + domain, "another."  + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_md( domains )
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        # should no longer the same cert
        status = TestEnv.get_certificate_status( domain )
        assert status['serial'] != cert1.get_serial() 
        TestEnv.check_md_complete(domain)
        # should have a 2 accounts now
        assert 2 == len(TestEnv.list_accounts())

    #-----------------------------------------------------------------------------------------------
    # create 2 MDs with ACMEv1, let them get a cert, change config to ACMEv2
    # check that both work and that only a single ACME acct is created
    # 
    def test_710_002(self):
        domain = self.test_domain

        # use ACMEv1 initially
        TestEnv.set_acme('acmev1')

        domainA = "a-" + domain
        domainB = "b-" + domain
        
        # generate config with two MDs
        domainsA = [ domainA, "www." + domainA ]
        domainsB = [ domainB, "www." + domainB ]

        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_line( "MDMembers auto" )
        conf.add_md( [ domainA ] )
        conf.add_md( [ domainB ] )
        conf.add_vhost(domainsA)
        conf.add_vhost(domainsB)
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domainsA )
        TestEnv.check_md( domainsB )
        # await drive completion
        assert TestEnv.await_completion( [ domainA, domainB ] )
        TestEnv.check_md_complete(domainsA[0])
        TestEnv.check_md_complete(domainsB[0])
        cert1 = TestEnv.get_cert(domainA)
        # should have a single account now
        assert 1 == len(TestEnv.list_accounts())
        
        # use ACMEv2 now for everything
        TestEnv.set_acme('acmev2')

        # change the MDs so that we need a new cert
        domainsA = [ domainA, "www." + domainA, "another."  + domainA ]
        domainsB = [ domainB, "www." + domainB, "another."  + domainB ]

        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_line( "MDMembers auto" )
        conf.add_md( [ domainA ] )
        conf.add_md( [ domainB ] )
        conf.add_vhost(domainsA)
        conf.add_vhost(domainsB)
        conf.install()

        # restart, gets cert
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domainA, domainB ] )
        TestEnv.check_md( domainsA )
        TestEnv.check_md( domainsB )
        TestEnv.check_md_complete(domainsA[0])
        cert2 = TestEnv.get_cert(domainA)
        # should no longer the same cert
        assert cert1.get_serial() != cert2.get_serial()
        # should have a 2 accounts now
        assert 2 == len(TestEnv.list_accounts())


    #-----------------------------------------------------------------------------------------------
    # create an MD with ACMEv1, let them get a cert, remove the explicit 
    # MDCertificateAuthority config and expect the new default to kick in.
    # 
    def test_710_003(self):
        domain = "a-" + self.test_domain
        domainb = "b-" + self.test_domain 

        # use ACMEv1 initially
        TestEnv.set_acme('acmev1')
        ca_url = TestEnv.ACME_URL
        
        domains = [ domain, "www." + domain ]
        conf = HttpdConf()
        conf.clear()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_line( "MDCertificateAgreement accepted" )
        conf.add_line( "MDMembers auto" )
        conf.start_md2( [ domain ] )
        conf.add_line( "MDCertificateAuthority %s" % (ca_url) )
        conf.end_md2()
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md( domains )
        assert TestEnv.await_completion( [ domain ] )
        assert (0, 0) == TestEnv.httpd_error_log_count()
        TestEnv.check_md(domains, ca=ca_url)
                
        # use ACMEv2 now, same MD, no CA url
        TestEnv.set_acme('acmev2')
        # this changes the default CA url
        assert TestEnv.ACME_URL_DEFAULT != ca_url
        
        conf = HttpdConf()
        conf.clear()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_line( "MDCertificateAgreement accepted" )
        conf.add_line( "MDMembers auto" )
        conf.start_md( [ domain ] )
        conf.end_md()
        conf.start_md2( [ domainb ] )
        # this willg get the reald Let's Encrypt URL assigned, turn off
        # auto renewal, so we will not talk to them
        conf.add_line( "MDRenewMode manual" )
        conf.end_md2()
        conf.add_vhost(domains)
        conf.add_vhost(domainb)
        conf.install()
        
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.httpd_error_log_count()
        # the existing MD was migrated to new CA url
        TestEnv.check_md(domains, ca=TestEnv.ACME_URL_DEFAULT)
        # the new MD got the new default anyway
        TestEnv.check_md([ domainb ], ca=TestEnv.ACME_URL_DEFAULT)

