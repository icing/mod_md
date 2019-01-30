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
from httplib import HTTPSConnection
from test_base import TestEnv
from test_base import HttpdConf
from test_base import CertUtil


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.initv2()
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
        TestEnv.initv2()
        TestEnv.apache_err_reset();
        TestEnv.clear_store()
        TestEnv.install_test_conf();

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard certificate with ACMEv1 
    #
    def test_720_000(self):
        domain = "test720-000-" + TestAuto.dns_uniq
        
        # switch to ACMEv1
        TestEnv.initv1()
        
        # generate config with DNS wildcard
        dnsList = [ domain, "*." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True )
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names( domain, dnsList )
        # await drive error as ACMEv1 does not accept DNS wildcards
        assert TestEnv.await_error( [ domain ] )

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard certificate with ACMEv2, no dns-01 supported
    #
    def test_720_001(self):
        domain = "test720-001-" + TestAuto.dns_uniq
        
        # generate config with DNS wildcard
        dnsList = [ domain, "*." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True )
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names( domain, dnsList )
        # await drive completion
        assert TestEnv.await_error( [ domain ] )


    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard certificate with ACMEv2, only dns-01 configured, invalid command path 
    #
    def test_720_002(self):
        domain = "test720-002-" + TestAuto.dns_uniq
        
        dns01cmd = ("%s/dns01-not-found.py" % TestEnv.TESTROOT)

        # generate config with DNS wildcard
        dnsList = [ domain, "*." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_ca_challenges( [ "dns-01" ] )
        conf.add_dns01_cmd( dns01cmd )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True )
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names( domain, dnsList )
        # await drive completion
        assert TestEnv.await_error( [ domain ] )

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard certificate with ACMEv2, only dns-01 configured, invalid command option 
    #
    def test_720_003(self):
        domain = "test720-003-" + TestAuto.dns_uniq
        
        dns01cmd = ("%s/dns01.py fail" % TestEnv.TESTROOT)

        # generate config with DNS wildcard
        dnsList = [ domain, "*." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_ca_challenges( [ "dns-01" ] )
        conf.add_dns01_cmd( dns01cmd )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True )
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names( domain, dnsList )
        # await drive completion
        assert TestEnv.await_error( [ domain ] )

    #-----------------------------------------------------------------------------------------------
    # test case: a wildcard certificate with ACMEv2, only dns-01 configured 
    #
    @pytest.mark.skipif(False, reason="not implemented yet")
    def test_720_004(self):
        domain = "test720-004-" + TestAuto.dns_uniq
        
        dns01cmd = ("%s/dns01.py" % TestEnv.TESTROOT)

        # generate config with DNS wildcard
        dnsList = [ domain, "*." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_ca_challenges( [ "dns-01" ] )
        conf.add_dns01_cmd( dns01cmd )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True )
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names( domain, dnsList )
        # await drive completion
        assert TestEnv.await_completion( [ domain ] )
        self._check_md_cert( dnsList )

        # check: SSL is running OK
        certA = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        assert [ dnsList[1], dnsList[0] ] == certA.get_san_list()

        # should have a single account now
        assert 1 == len(TestEnv.list_accounts())

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


