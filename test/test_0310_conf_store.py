# test mod_md basic configurations

import pytest
import os

from configparser import ConfigParser
from TestEnv import TestEnv
from TestHttpdConf import HttpdConf

config = ConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

SEC_PER_DAY = 24 * 60 * 60
MS_PER_DAY = SEC_PER_DAY * 1000
NS_PER_DAY = MS_PER_DAY * 1000


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.check_acme()
    

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestConf:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    # test case: no md definitions in config
    def test_310_001(self):
        HttpdConf(text="").install()
        assert TestEnv.apache_restart() == 0
        jout = TestEnv.a2md(["list"])['jout']
        assert 0 == len(jout["output"])

    # test case: add md definitions on empty store
    @pytest.mark.parametrize("confline,dns_lists,md_count", [
        ("MDomain testdomain.org www.testdomain.org mail.testdomain.org", 
            [["testdomain.org", "www.testdomain.org", "mail.testdomain.org"]], 1),
        ("""MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDomain testdomain2.org www.testdomain2.org mail.testdomain2.org""", 
            [["testdomain.org", "www.testdomain.org", "mail.testdomain.org"],
             ["testdomain2.org", "www.testdomain2.org", "mail.testdomain2.org"]], 2)
    ])
    def test_310_100(self, confline, dns_lists, md_count):
        HttpdConf(text=confline).install()
        assert TestEnv.apache_restart() == 0
        for i in range(0, len(dns_lists)):
            TestEnv.check_md(dns_lists[i], state=1)

    # test case: add managed domains as separate steps
    def test_310_101(self):
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDomain testdomain2.org www.testdomain2.org mail.testdomain2.org
            """).install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)
        TestEnv.check_md(["testdomain2.org", "www.testdomain2.org", "mail.testdomain2.org"], state=1)

    # test case: add dns to existing md
    def test_310_102(self):
        assert TestEnv.a2md(["add", "testdomain.org", "www.testdomain.org"])['rv'] == 0
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)

    # test case: add new md definition with acme url, acme protocol, acme agreement
    def test_310_103(self):
        HttpdConf(text="""
            MDCertificateAuthority http://acme.test.org:4000/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://acme.test.org:4000/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        name = "testdomain.org"
        TestEnv.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                         ca="http://acme.test.org:4000/directory", protocol="ACME",
                         agreement="http://acme.test.org:4000/terms/v1")

    # test case: add to existing md: acme url, acme protocol
    def test_310_104(self):
        name = "testdomain.org"
        HttpdConf(local_ca=False, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                         ca=TestEnv.ACME_URL_DEFAULT, protocol="ACME")
        HttpdConf(local_ca=False, text="""
            MDCertificateAuthority http://acme.test.org:4000/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://acme.test.org:4000/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                         ca="http://acme.test.org:4000/directory", protocol="ACME",
                         agreement="http://acme.test.org:4000/terms/v1")

    # test case: add new md definition with server admin
    def test_310_105(self):
        HttpdConf(text="""
            ServerAdmin mailto:admin@testdomain.org
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        name = "testdomain.org"
        TestEnv.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                         contacts=["mailto:admin@testdomain.org"])

    # test case: add to existing md: server admin
    def test_310_106(self):
        name = "testdomain.org"
        assert TestEnv.a2md(["add", name, "www.testdomain.org", "mail.testdomain.org"])['rv'] == 0
        HttpdConf(text="""
            ServerAdmin mailto:admin@testdomain.org
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                         contacts=["mailto:admin@testdomain.org"])

    # test case: assign separate contact info based on VirtualHost
    def test_310_107(self):
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDomain testdomain2.org www.testdomain2.org mail.testdomain2.org

            <VirtualHost *:12346>
                ServerName testdomain.org
                ServerAlias www.testdomain.org
                ServerAdmin mailto:admin@testdomain.org
            </VirtualHost>

            <VirtualHost *:12346>
                ServerName testdomain2.org
                ServerAlias www.testdomain2.org
                ServerAdmin mailto:admin@testdomain2.org
            </VirtualHost>
            """).install()
        assert TestEnv.apache_restart() == 0
        name1 = "testdomain.org"
        name2 = "testdomain2.org"
        TestEnv.check_md([name1, "www." + name1, "mail." + name1], state=1, contacts=["mailto:admin@" + name1])
        TestEnv.check_md([name2, "www." + name2, "mail." + name2], state=1, contacts=["mailto:admin@" + name2])

    # test case: normalize names - lowercase
    def test_310_108(self):
        HttpdConf(text="""
            MDomain testdomain.org WWW.testdomain.org MAIL.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)

    # test case: default drive mode - auto
    def test_310_109(self):
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-mode'] == 1

    # test case: drive mode manual
    def test_310_110(self):
        HttpdConf(text="""
            MDRenewMode manual
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-mode'] == 0

    # test case: drive mode auto
    def test_310_111(self):
        HttpdConf(text="""
            MDRenewMode auto
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-mode'] == 1

    # test case: drive mode always
    def test_310_112(self):
        HttpdConf(text="""
            MDRenewMode always
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-mode'] == 2

    # test case: renew window - 14 days
    def test_310_113a(self):
        HttpdConf(text="""
            MDRenewWindow 14d
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-window'] == '14d'

    # test case: renew window - 10 percent
    def test_310_113b(self):
        HttpdConf(text="""
            MDRenewWindow 10%
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-window'] == '10%'
        
    # test case: ca challenge type - http-01
    def test_310_114(self):
        HttpdConf(text="""
            MDCAChallenges http-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['ca']['challenges'] == ['http-01']

    # test case: ca challenge type - http-01
    def test_310_115(self):
        HttpdConf(text="""
            MDCAChallenges tls-alpn-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['ca']['challenges'] == ['tls-alpn-01']

    # test case: ca challenge type - all
    def test_310_116(self):
        HttpdConf(text="""
            MDCAChallenges http-01 tls-alpn-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['ca']['challenges'] == ['http-01', 'tls-alpn-01']

    # test case: automatically collect md names from vhost config
    def test_310_117(self):
        HttpdConf(text="""
            MDMember auto
            MDomain testdomain.org

            <VirtualHost *:12346>
                ServerName testdomain.org
                ServerAlias test.testdomain.org
                ServerAlias mail.testdomain.org
                DocumentRoot htdocs
                SSLEngine on
            </VirtualHost>
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['domains'] == \
               ['testdomain.org', 'test.testdomain.org', 'mail.testdomain.org']

    # add renew window to existing md
    def test_310_118(self):
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        HttpdConf(text="""
            MDRenewWindow 14d
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_md_status("testdomain.org")
        assert stat['renew-window'] == '14d'

    # test case: set RSA key length 2048
    def test_310_119(self):
        HttpdConf(text="""
            MDPrivateKeys RSA 2048
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 2048
        }

    # test case: set RSA key length 4096
    def test_310_120(self):
        HttpdConf(text="""
            MDPrivateKeys RSA 4096
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 4096
        }

    # test case: require HTTPS
    def test_310_121(self):
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDRequireHttps temporary
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['require-https'] == "temporary"

    # test case: require OCSP stapling
    def test_310_122(self):
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDMustStaple on
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['must-staple'] is True

    # test case: remove managed domain from config
    def test_310_200(self):
        dns_list = ["testdomain.org", "www.testdomain.org", "mail.testdomain.org"]
        TestEnv.a2md(["add"] + dns_list)
        TestEnv.check_md(dns_list, state=1)
        conf = HttpdConf()
        conf.install()
        assert TestEnv.apache_restart() == 0
        # check: md stays in store
        TestEnv.check_md(dns_list, state=1)

    # test case: remove alias DNS from managed domain
    def test_310_201(self):
        dns_list = ["testdomain.org", "test.testdomain.org", "www.testdomain.org", "mail.testdomain.org"]
        TestEnv.a2md(["add"] + dns_list)
        TestEnv.check_md(dns_list, state=1)
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # check: DNS has been removed from md in store
        TestEnv.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)

    # test case: remove primary name from managed domain
    def test_310_202(self):
        dns_list = ["name.testdomain.org", "testdomain.org", "www.testdomain.org", "mail.testdomain.org"]
        TestEnv.a2md(["add"] + dns_list)
        TestEnv.check_md(dns_list, state=1)
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # check: md overwrite previous name and changes name
        TestEnv.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], 
                         md="testdomain.org", state=1)

    # test case: remove one md, keep another
    def test_310_203(self):
        dns_list1 = ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        dns_list2 = ["testdomain.org", "www.testdomain.org", "mail.testdomain.org"]
        TestEnv.a2md(["add"] + dns_list1)
        TestEnv.a2md(["add"] + dns_list2)
        TestEnv.check_md(dns_list1, state=1)
        TestEnv.check_md(dns_list2, state=1)
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # all mds stay in store
        TestEnv.check_md(dns_list1, state=1)
        TestEnv.check_md(dns_list2, state=1)

    # test case: remove ca info from md, should switch over to new defaults
    def test_310_204(self):
        name = "testdomain.org"
        HttpdConf(local_ca=False, text="""
            MDCertificateAuthority http://acme.test.org:4000/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://acme.test.org:4000/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # setup: sync with ca info removed
        HttpdConf(local_ca=False, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                         ca=TestEnv.ACME_URL_DEFAULT, protocol="ACME")

    # test case: remove server admin from md
    def test_310_205(self):
        name = "testdomain.org"
        HttpdConf(text="""
            ServerAdmin mailto:admin@testdomain.org
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # setup: sync with admin info removed
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # check: md stays the same with previous admin info
        TestEnv.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                         contacts=["mailto:admin@testdomain.org"])

    # test case: remove renew window from conf -> fallback to default
    def test_310_206(self):
        HttpdConf(text="""
            MDRenewWindow 14d
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-window'] == '14d'
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # check: renew window not set
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-window'] == '33%'

    # test case: remove drive mode from conf -> fallback to default (auto)
    @pytest.mark.parametrize("renew_mode,exp_code", [
        ("manual", 0), 
        ("auto", 1), 
        ("always", 2)
    ])
    def test_310_207(self, renew_mode, exp_code):
        HttpdConf(text="""
            MDRenewMode %s
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """ % renew_mode).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-mode'] == exp_code
        #
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-mode'] == 1

    # test case: remove challenges from conf -> fallback to default (not set)
    def test_310_208(self):
        HttpdConf(text="""
            MDCAChallenges http-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['ca']['challenges'] == ['http-01']
        #
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert 'challenges' not in TestEnv.a2md(["list"])['jout']['output'][0]['ca']

    # test case: specify RSA key
    @pytest.mark.parametrize("key_size", ["2048", "4096"])
    def test_310_209(self, key_size):
        HttpdConf(text="""
            MDPrivateKeys RSA %s
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """ % key_size).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['privkey']['type'] == "RSA"
        #
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert "privkey" not in TestEnv.a2md(["list"])['jout']['output'][0]

    # test case: require HTTPS
    @pytest.mark.parametrize("mode", ["temporary", "permanent"])
    def test_310_210(self, mode):
        HttpdConf(text="""
            <MDomainSet testdomain.org>
                MDMember www.testdomain.org mail.testdomain.org
                MDRequireHttps %s
            </MDomainSet>
            """ % mode).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['require-https'] == mode, \
            "Unexpected HTTPS require mode in store. config: {}".format(mode)
        #
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert "require-https" not in TestEnv.a2md(["list"])['jout']['output'][0], \
            "HTTPS require still persisted in store. config: {}".format(mode)

    # test case: require OCSP stapling
    def test_310_211(self):
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDMustStaple on
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['must-staple'] is True
        #
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['must-staple'] is False

    # test case: reorder DNS names in md definition
    def test_310_300(self):
        dns_list = ["testdomain.org", "mail.testdomain.org", "www.testdomain.org"]
        TestEnv.a2md(["add"] + dns_list)
        TestEnv.check_md(dns_list, state=1)
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # check: dns list changes
        TestEnv.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)

    # test case: move DNS from one md to another
    def test_310_301(self):
        TestEnv.a2md(["add", "testdomain.org", "www.testdomain.org", "mail.testdomain.org", "mail.testdomain2.org"])
        TestEnv.a2md(["add", "testdomain2.org", "www.testdomain2.org"])
        TestEnv.check_md(["testdomain.org", "www.testdomain.org",
                          "mail.testdomain.org", "mail.testdomain2.org"], state=1)
        TestEnv.check_md(["testdomain2.org", "www.testdomain2.org"], state=1)        
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDomain testdomain2.org www.testdomain2.org mail.testdomain2.org
            """).install()
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)
        TestEnv.check_md(["testdomain2.org", "www.testdomain2.org", "mail.testdomain2.org"], state=1)

    # test case: change ca info
    def test_310_302(self):
        name = "testdomain.org"
        HttpdConf(local_ca=False, text="""
            MDCertificateAuthority http://acme.test.org:4000/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://acme.test.org:4000/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # setup: sync with changed ca info
        HttpdConf(local_ca=False, text="""
            ServerAdmin mailto:webmaster@testdomain.org

            MDCertificateAuthority http://somewhere.com:6666/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://somewhere.com:6666/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # check: md stays the same with previous ca info
        TestEnv.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                         ca="http://somewhere.com:6666/directory", protocol="ACME",
                         agreement="http://somewhere.com:6666/terms/v1")

    # test case: change server admin
    def test_310_303(self):
        name = "testdomain.org"
        HttpdConf(text="""
            ServerAdmin mailto:admin@testdomain.org
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # setup: sync with changed admin info
        HttpdConf(local_ca=False, text="""
            ServerAdmin mailto:webmaster@testdomain.org

            MDCertificateAuthority http://somewhere.com:6666/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://somewhere.com:6666/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        # check: md stays the same with previous admin info
        TestEnv.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                         contacts=["mailto:webmaster@testdomain.org"])

    # test case: change drive mode - manual -> auto -> always
    def test_310_304(self):
        HttpdConf(text="""
            MDRenewMode manual
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-mode'] == 0
        # test case: drive mode auto
        HttpdConf(text="""
            MDRenewMode auto
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-mode'] == 1
        # test case: drive mode always
        HttpdConf(text="""
            MDRenewMode always
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['renew-mode'] == 2

    # test case: change config value for renew window, use various syntax alternatives
    def test_310_305(self):
        HttpdConf(text="""
            MDRenewWindow 14d
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        md = TestEnv.a2md(["list"])['jout']['output'][0]
        assert md['renew-window'] == '14d'
        HttpdConf(text="""
            MDRenewWindow 10
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        md = TestEnv.a2md(["list"])['jout']['output'][0]
        assert md['renew-window'] == '10d'
        HttpdConf(text="""
            MDRenewWindow 10%
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        md = TestEnv.a2md(["list"])['jout']['output'][0]
        assert md['renew-window'] == '10%'

    # test case: change challenge types - http -> tls-sni -> all
    def test_310_306(self):
        HttpdConf(text="""
            MDCAChallenges http-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['ca']['challenges'] == ['http-01']
        # test case: drive mode auto
        HttpdConf(text="""
            MDCAChallenges tls-alpn-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['ca']['challenges'] == ['tls-alpn-01']
        # test case: drive mode always
        HttpdConf(text="""
            MDCAChallenges http-01 tls-alpn-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['ca']['challenges'] == ['http-01', 'tls-alpn-01']

    # test case:  RSA key length: 4096 -> 2048 -> 4096
    def test_310_307(self):
        HttpdConf(text="""
            MDPrivateKeys RSA 4096
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 4096
        }
        HttpdConf(text="""
            MDPrivateKeys RSA 2048
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 2048
        }
        HttpdConf(text="""
            MDPrivateKeys RSA 4096
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 4096
        }

    # test case: change HTTPS require settings on existing md
    def test_310_308(self):
        # setup: nothing set
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert "require-https" not in TestEnv.a2md(["list"])['jout']['output'][0]
        # test case: temporary redirect
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDRequireHttps temporary
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['require-https'] == "temporary"
        # test case: permanent redirect
        HttpdConf(text="""
            <MDomainSet testdomain.org>
                MDMember www.testdomain.org mail.testdomain.org
                MDRequireHttps permanent
            </MDomainSet>
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['require-https'] == "permanent"

    # test case: change OCSP stapling settings on existing md
    def test_310_309(self):
        # setup: nothing set
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['must-staple'] is False
        # test case: OCSP stapling on
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDMustStaple on
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['must-staple'] is True
        # test case: OCSP stapling off
        HttpdConf(text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDMustStaple off
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'][0]['must-staple'] is False

    # test case: change renew window parameter
    @pytest.mark.parametrize("window", [
        "0%", "33d", "40%"
    ])
    def test_310_310(self, window):
        # non-default renewal setting
        domain = self.test_domain
        conf = HttpdConf()
        conf.add_admin("admin@" + domain)
        conf.start_md([domain])
        conf.add_drive_mode("manual")
        conf.add_renew_window(window)
        conf.end_md()
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_md_status(domain)
        assert stat["renew-window"] == window

    # test case: add dns name on existing valid md
    def test_310_400(self):
        # setup: create complete md in store
        domain = self.test_domain
        name = "www." + domain
        assert TestEnv.a2md(["add", name, "test1." + domain])['rv'] == 0
        assert TestEnv.a2md(["update", name, "contacts", "admin@" + name])['rv'] == 0
        assert TestEnv.a2md(["update", name, "agreement", TestEnv.ACME_TOS])['rv'] == 0
        assert TestEnv.apache_start() == 0
        # setup: drive it
        assert TestEnv.a2md(["-v", "drive", name])['rv'] == 0
        assert TestEnv.a2md(["list", name])['jout']['output'][0]['state'] == TestEnv.MD_S_COMPLETE

        # remove one domain -> status stays COMPLETE
        assert TestEnv.a2md(["update", name, "domains", name])['rv'] == 0
        assert TestEnv.a2md(["list", name])['jout']['output'][0]['state'] == TestEnv.MD_S_COMPLETE
        
        # add other domain -> status INCOMPLETE
        assert TestEnv.a2md(["update", name, "domains", name, "test2." + domain])['rv'] == 0
        assert TestEnv.a2md(["list", name])['jout']['output'][0]['state'] == TestEnv.MD_S_INCOMPLETE

    # test case: change ca info
    def test_310_401(self):
        # setup: create complete md in store
        domain = self.test_domain
        name = "www." + domain
        assert TestEnv.a2md(["add", name])['rv'] == 0
        assert TestEnv.a2md(["update", name, "contacts", "admin@" + name])['rv'] == 0
        assert TestEnv.a2md(["update", name, "agreement", TestEnv.ACME_TOS])['rv'] == 0
        assert TestEnv.apache_start() == 0
        # setup: drive it
        assert TestEnv.a2md(["drive", name])['rv'] == 0
        assert TestEnv.a2md(["list", name])['jout']['output'][0]['state'] == TestEnv.MD_S_COMPLETE
        # setup: change CA URL
        assert TestEnv.a2md(["update", name, "ca", TestEnv.ACME_URL_DEFAULT])['rv'] == 0
        # check: state stays COMPLETE
        assert TestEnv.a2md(["list", name])['jout']['output'][0]['state'] == TestEnv.MD_S_COMPLETE

    # test case: change the store dir
    def test_310_500(self):
        HttpdConf(text="""
            MDStoreDir md-other
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.a2md(["list"])['jout']['output'] == []
        TestEnv.set_store_dir("md-other")
        TestEnv.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)
        TestEnv.clear_store()
        TestEnv.set_store_dir_default()

    # test case: place an unexpected file into the store, check startup survival, see #218
    def test_310_501(self):
        # setup: create complete md in store
        domain = self.test_domain
        conf = HttpdConf()
        conf.add_admin("admin@" + domain)
        conf.start_md([domain])
        conf.end_md()
        conf.add_vhost(domain)
        conf.add_line('LogLevel md:trace1')
        conf.install()
        assert TestEnv.apache_restart() == 0
        # add a file at top level
        assert TestEnv.await_completion([domain])
        fpath = os.path.join(TestEnv.store_domains(), "wrong.com")
        with open(fpath, 'w') as fd:
            fd.write("this does not belong here\n")
        assert TestEnv.apache_restart() == 0
