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


class TestAuto:

    @classmethod
    def setup_class(cls):
        time.sleep(1)
        cls.dns_uniq = "%d.org" % time.time()
        cls.TMP_CONF = os.path.join(TestEnv.GEN_DIR, "auto.conf")

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.apache_err_reset();
        TestEnv.clear_store()
        TestEnv.install_test_conf();

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    #-----------------------------------------------------------------------------------------------
    # create a MD with ACMEv1, let it get a cert, change config to ACMEv2
    # 
    def test_710_001(self):
        domain = "test710-001-" + TestAuto.dns_uniq

        # use ACMEv1 initially
        TestEnv.set_acme('acmev1')
        
        # generate config with one MD, restart, gets cert
        dns_list = [ domain, "www." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_md( dns_list )
        conf.add_vhost(TestEnv.HTTPS_PORT, domain, aliasList=[ dns_list[1] ], withSSL=True)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        self._check_md_cert( dns_list )
        cert1 = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        assert domain in cert1.get_san_list()
 
        # use ACMEv2 now for everything
        TestEnv.set_acme('acmev2')

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_md( dns_list )
        conf.add_vhost(TestEnv.HTTPS_PORT, domain, aliasList=[ dns_list[1] ], withSSL=True)
        conf.install()
        # restart, gets cert
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        self._check_md_cert( dns_list )
        cert2 = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        # should still be the same cert as it remains valid
        assert cert1.get_serial() == cert2.get_serial()
        
        # change the MD so that we need a new cert
        dns_list = [ domain, "www." + domain, "another."  + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_md( dns_list )
        conf.add_vhost(TestEnv.HTTPS_PORT, domain, aliasList=[ dns_list[1] ], withSSL=True)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domain ] )
        self._check_md_cert( dns_list )
        cert3 = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        # should no longer the same cert
        assert cert1.get_serial() != cert3.get_serial()

    #-----------------------------------------------------------------------------------------------
    # create 2 MDs with ACMEv1, let them get a cert, change config to ACMEv2
    # check that both work and that only a single ACME acct is created
    # 
    def test_710_002(self):
        domain = "test710-002-" + TestAuto.dns_uniq

        # use ACMEv1 initially
        TestEnv.set_acme('acmev1')

        domainA = "a-" + domain
        domainB = "b-" + domain
        
        # generate config with two MDs
        dnsListA = [ domainA, "www." + domainA ]
        dnsListB = [ domainB, "www." + domainB ]

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_line( "MDMembers auto" )
        conf.add_md( [ domainA ] )
        conf.add_md( [ domainB ] )
        conf.add_vhost( TestEnv.HTTPS_PORT, domainA, aliasList=dnsListA[1:], withSSL=True )
        conf.add_vhost( TestEnv.HTTPS_PORT, domainB, aliasList=dnsListB[1:], withSSL=True )
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names( domainA, dnsListA )
        self._check_md_names( domainB, dnsListB )
        # await drive completion
        assert TestEnv.await_completion( [ domainA, domainB ] )
        self._check_md_cert(dnsListA)
        self._check_md_cert(dnsListB)
        self._check_md_cert( dnsListA )
        cert1 = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domainA)
        # should have a single account now
        assert 1 == len(TestEnv.list_accounts())
        
        # use ACMEv2 now for everything
        TestEnv.set_acme('acmev2')

        # change the MDs so that we need a new cert
        dnsListA = [ domainA, "www." + domainA, "another."  + domainA ]
        dnsListB = [ domainB, "www." + domainB, "another."  + domainB ]

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_line( "MDMembers auto" )
        conf.add_md( [ domainA ] )
        conf.add_md( [ domainB ] )
        conf.add_vhost( TestEnv.HTTPS_PORT, domainA, aliasList=dnsListA[1:], withSSL=True )
        conf.add_vhost( TestEnv.HTTPS_PORT, domainB, aliasList=dnsListB[1:], withSSL=True )
        conf.install()

        # restart, gets cert
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([ domainA, domainB ] )
        self._check_md_names( domainA, dnsListA )
        self._check_md_names( domainB, dnsListB )
        self._check_md_cert( dnsListA )
        cert2 = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domainA)
        # should no longer the same cert
        assert cert1.get_serial() != cert2.get_serial()
        # should have a 2 accounts now
        assert 2 == len(TestEnv.list_accounts())


    # --------- _utils_ ---------

    def _check_md_names(self, name, dns_list):
        md = TestEnv.a2md([ "-j", "list", name ])['jout']['output'][0]
        assert md['name'] == name
        assert md['domains'] == dns_list


    def _check_md_cert(self, dns_list):
        name = dns_list[0]
        md = TestEnv.a2md([ "list", name ])['jout']['output'][0]
        # check tos agreement, cert url
        assert md['state'] == TestEnv.MD_S_COMPLETE
        assert os.path.isfile( TestEnv.path_domain_privkey(name) )
        assert os.path.isfile( TestEnv.path_domain_pubcert(name) )


