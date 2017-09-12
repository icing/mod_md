# test mod_md basic configurations

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
        self.test_n = re.match("test_(.+)", method.__name__).group(1)
        self.test_domain =  ("%s-" % self.test_n) + TestAuto.dns_uniq

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    #-----------------------------------------------------------------------------------------------
    # create a MD not used in any virtual host, auto drive should NOT pick it up
    # 
    def test_7001(self):
        domain = self.test_domain

        # generate config with one MD
        dns_list = [ domain, "www." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_drive_mode( "auto" )
        conf.add_md( dns_list )
        conf.install()

        # restart, check that MD is synched to store
        assert TestEnv.apache_restart() == 0
        self._check_md_names(domain, dns_list)
        time.sleep( 2 )
        # assert drive did not start
        md = TestEnv.a2md([ "-j", "list", domain ])['jout']['output'][0]
        assert md['state'] == TestEnv.MD_S_INCOMPLETE
        assert 'account' not in md['ca']
        assert TestEnv.apache_err_scan( re.compile('.*\[md:debug\].*no mds to auto drive') )

        # add vhost for MD, restart should drive it
        conf.add_vhost(TestEnv.HTTPS_PORT, domain, aliasList=[ dns_list[1] ], withSSL=True)
        conf.install()
        assert TestEnv.apache_restart() == 0

        assert TestEnv.await_completion([ domain ], 30)
        self._check_md_cert( dns_list )
        cert = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        assert domain in cert.get_san_list()

        # challenges should have been removed
        TestEnv.check_dir_empty( TestEnv.path_challenges() )

        # file system needs to have correct permissions
        TestEnv.check_file_permissions( domain )

    #-----------------------------------------------------------------------------------------------
    # test case: same as test_7001, but with two parallel managed domains
    #
    def test_7002(self):
        domainA = ("%sa-" % self.test_n) + TestAuto.dns_uniq
        domainB = ("%sb-" % self.test_n) + TestAuto.dns_uniq
        
        # generate config with two MDs
        dnsListA = [ domainA, "www." + domainA ]
        dnsListB = [ domainB, "www." + domainB ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@example.org" )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsListA )
        conf.add_md( dnsListB )
        conf.add_vhost( TestEnv.HTTPS_PORT, domainA, aliasList=[ dnsListA[1] ], withSSL=True )
        conf.add_vhost( TestEnv.HTTPS_PORT, domainB, aliasList=[ dnsListB[1] ], withSSL=True )
        conf.install()

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names( domainA, dnsListA )
        self._check_md_names( domainB, dnsListB )
        # await drive completion
        assert TestEnv.await_completion( [ domainA, domainB ], 30 )
        self._check_md_cert(dnsListA)
        self._check_md_cert(dnsListB)

        # check: SSL is running OK
        certA = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domainA)
        assert dnsListA == certA.get_san_list()
        certB = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domainB)
        assert dnsListB == certB.get_san_list()


    #-----------------------------------------------------------------------------------------------
    # test case: one MD, that covers two vhosts
    #
    def test_7003(self):
        domain = self.test_domain
        nameA = "test-a." + domain
        nameB = "test-b." + domain
        dns_list = [ domain, nameA, nameB ]

        # generate 1 MD and 2 vhosts
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, nameA, aliasList=[], docRoot="htdocs/a", 
                        withSSL=True, certPath=TestEnv.path_domain_pubcert( domain ), 
                        keyPath=TestEnv.path_domain_privkey( domain ) )
        conf.add_vhost( TestEnv.HTTPS_PORT, nameB, aliasList=[], docRoot="htdocs/b", 
                        withSSL=True, certPath=TestEnv.path_domain_pubcert( domain ), 
                        keyPath=TestEnv.path_domain_privkey( domain ) )
        conf.install()

        # create docRoot folder
        self._write_res_file( os.path.join(TestEnv.APACHE_HTDOCS_DIR, "a"), "name.txt", nameA )
        self._write_res_file( os.path.join(TestEnv.APACHE_HTDOCS_DIR, "b"), "name.txt", nameB )

        # restart (-> drive), check that MD was synched and completes
        assert TestEnv.apache_restart() == 0
        self._check_md_names( domain, dns_list )
        assert TestEnv.await_completion( [ domain ], 30 )
        self._check_md_cert( dns_list )

        # check: SSL is running OK
        certA = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, nameA)
        assert nameA in certA.get_san_list()
        certB = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, nameB)
        assert nameB in certB.get_san_list()
        assert certA.get_serial() == certB.get_serial()
        
        assert TestEnv.get_content( nameA, "/name.txt" ) == nameA
        assert TestEnv.get_content( nameB, "/name.txt" ) == nameB


    #-----------------------------------------------------------------------------------------------
    # test case: drive with using single challenge type explicitly
    #
    @pytest.mark.parametrize("challengeType", [ 
        ("tls-sni-01"), 
        ("http-01")
    ])
    def test_7004(self, challengeType):
        domain = self.test_domain
        dns_list = [ domain, "www." + domain ]

        # generate 1 MD and 1 vhost
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_drive_mode( "auto" )
        conf.add_ca_challenges( [ challengeType ] )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dns_list[1] ], withSSL=True )
        conf.install()

        # restart (-> drive), check that MD was synched and completes
        assert TestEnv.apache_restart() == 0
        self._check_md_names(domain, dns_list)
        assert TestEnv.await_completion( [ domain ], 30 )
        self._check_md_cert(dns_list)
        
        # check SSL running OK
        cert = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        assert domain in cert.get_san_list()

    #-----------------------------------------------------------------------------------------------
    # test case: drive_mode manual, check that server starts, but requests to domain are 503'd
    #
    def test_7005(self):
        domain = self.test_domain
        nameA = "test-a." + domain
        dns_list = [ domain, nameA ]

        # generate 1 MD and 1 vhost
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_drive_mode( "manual" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, nameA, aliasList=[], docRoot="htdocs/a", 
                        withSSL=True, certPath=TestEnv.path_domain_pubcert( domain ), 
                        keyPath=TestEnv.path_domain_privkey( domain ) )
        conf.install()

        # create docRoot folder
        self._write_res_file(os.path.join(TestEnv.APACHE_HTDOCS_DIR, "a"), "name.txt", nameA)

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names(domain, dns_list)
        assert not TestEnv.await_completion( [ domain ], 2 )
        
        # check: that request to domains give 503 Service Unavailable
        cert1 = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, nameA)
        assert nameA in cert1.get_san_list()
        assert TestEnv.getStatus(nameA, "/name.txt") == 503

        # check temporary cert from server
        cert2 = CertUtil( TestEnv.path_fallback_cert( domain ) )
        assert cert1.get_serial() == cert2.get_serial(), \
            "Unexpected temporary certificate on vhost %s. Expected cn: %s , but found cn: %s" % ( nameA, cert2.get_cn(), cert1.get_cn() )

    #-----------------------------------------------------------------------------------------------
    # test case: drive MD with only invalid challenges, domains should stay 503'd
    #
    def test_7006(self):
        domain = self.test_domain
        nameA = "test-a." + domain
        dns_list = [ domain, nameA ]

        # generate 1 MD, 1 vhost
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_ca_challenges([ "invalid-01", "invalid-02" ])
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, nameA, aliasList=[], docRoot="htdocs/a", 
                        withSSL=True, certPath=TestEnv.path_domain_pubcert( domain ), 
                        keyPath=TestEnv.path_domain_privkey( domain ) )
        conf.install()

        # create docRoot folder
        self._write_res_file(os.path.join(TestEnv.APACHE_HTDOCS_DIR, "a"), "name.txt", nameA)

        # restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        self._check_md_names(domain, dns_list)
        time.sleep( 2 )
        # assert drive did not start
        md = TestEnv.a2md([ "-j", "list", domain ])['jout']['output'][0]
        assert md['state'] == TestEnv.MD_S_INCOMPLETE
        assert 'account' not in md['ca']
        assert TestEnv.apache_err_scan( re.compile('.*\[md:warn\].*the server offers no ACME challenge that is configured for this MD') )

        # check: that request to domains give 503 Service Unavailable
        cert = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, nameA)
        assert nameA in cert.get_san_list()
        assert TestEnv.getStatus(nameA, "/name.txt") == 503


    #-----------------------------------------------------------------------------------------------
    # MD not used in any virtual host, with drive mode 'always'
    # auto drive *should* pick it up
    #
    def test_7007(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_drive_mode( "always" )
        conf.add_md( dns_list )
        conf.install()

        # - restart (-> drive), check that md is in store
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], 30 )
        assert TestEnv.apache_restart() == 0
        self._check_md_cert( dns_list )

    #-----------------------------------------------------------------------------------------------
    # Specify a non-working http proxy
    #
    def test_7008(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_drive_mode( "always" )
        conf.add_http_proxy( "http://localhost:1" )
        conf.add_md( dns_list )
        conf.install()

        # - restart (-> drive)
        assert TestEnv.apache_restart() == 0
        time.sleep( 2 )
        # assert drive did not start
        md = TestEnv.a2md([ "-j", "list", domain ])['jout']['output'][0]
        assert md['state'] == TestEnv.MD_S_INCOMPLETE
        assert 'account' not in md['ca']
        assert TestEnv.apache_err_scan( re.compile('.*\[md:debug\].*Connection refused: ') )

    #-----------------------------------------------------------------------------------------------
    # Specify a valid http proxy
    #
    def test_7008a(self):
        domain = self.test_domain
        dns_list = [ domain ]

        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_drive_mode( "always" )
        conf.add_http_proxy( "http://localhost:%s"  % TestEnv.HTTP_PROXY_PORT)
        conf.add_md( dns_list )
        conf.install()

        # - restart (-> drive), check that md is in store
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], 30 )
        assert TestEnv.apache_restart() == 0
        self._check_md_cert( dns_list )

    #-----------------------------------------------------------------------------------------------
    # Force cert renewal due to critical remaining valid duration
    # Assert that new cert activation is delayed
    # 
    def test_7009(self):
        domain = self.test_domain
        dns_list = [ domain ]

        # prepare md
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@" + domain )
        conf.add_drive_mode( "auto" )
        conf.add_renew_window( "10d" )
        conf.add_md( dns_list )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[], withSSL=True )
        conf.install()

        # restart (-> drive), check that md+cert is in store, TLS is up
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], 30 )
        self._check_md_cert( dns_list )
        cert1 = CertUtil( TestEnv.path_domain_pubcert(domain) )
        # fetch cert from server
        cert2 = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        assert cert1.get_serial() == cert2.get_serial()

        # create self-signed cert, with critical remaining valid duration -> drive again
        CertUtil.create_self_signed_cert( [domain], { "notBefore": -120, "notAfter": 9  })
        cert3 = CertUtil( TestEnv.path_domain_pubcert(domain) )
        assert cert3.get_serial() == 1000
        time.sleep(1)
        assert TestEnv.a2md([ "list", domain])['jout']['output'][0]['renew'] == True
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], 30 )

        # fetch cert from server -> self-signed still active, activation of new ACME is delayed
        cert4 = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        assert cert4.get_serial() == cert3.get_serial()
        time.sleep( 1 )

        # restart -> new ACME cert becomes active
        assert TestEnv.apache_stop() == 0
        assert TestEnv.apache_start() == 0
        time.sleep( 1 )
        cert5 = CertUtil.load_server_cert(TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT, domain)
        assert cert5.get_serial() != cert3.get_serial()


    # --------- _utils_ ---------

    def _write_res_file(self, docRoot, name, content):
        if not os.path.exists(docRoot):
            os.makedirs(docRoot)
        open(os.path.join(docRoot, name), "w").write(content)


    def _check_md_names(self, name, dns_list):
        md = TestEnv.a2md([ "-j", "list", name ])['jout']['output'][0]
        assert md['name'] == name
        assert md['domains'] == dns_list


    def _check_md_cert(self, dns_list):
        name = dns_list[0]
        md = TestEnv.a2md([ "list", name ])['jout']['output'][0]
        # check tos agreement, cert url
        assert md['state'] == TestEnv.MD_S_COMPLETE
        assert "url" in md['cert']
        assert os.path.isfile( TestEnv.path_domain_privkey(name) )
        assert os.path.isfile( TestEnv.path_domain_pubcert(name) )

