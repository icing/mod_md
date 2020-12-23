# test mod_md status resources

import os
import re

from TestEnv import TestEnv
from TestHttpdConf import HttpdConf
from shutil import copyfile


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.APACHE_CONF_SRC = "data/test_auto"
    TestEnv.check_acme()
    TestEnv.clear_store()
    HttpdConf().install()
    

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestStatus:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # simple MD, drive it, check status before activation
    def test_920_001(self):
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([domain], restart=False)
        # we started without a valid certificate, so we expect /.httpd/certificate-status
        # to not give information about one and - since we waited for the ACME signup
        # to complete - to give information in 'renewal' about the new cert.
        status = TestEnv.get_certificate_status(domain)
        assert 'sha256-fingerprint' not in status
        assert 'valid' not in status
        assert 'renewal' in status
        assert 'valid' in status['renewal']['cert']
        assert 'sha256-fingerprint' in status['renewal']['cert']['rsa']
        # restart and activate
        # once activated, the staging must be gone and attributes exist for the active cert
        assert TestEnv.apache_restart() == 0
        status = TestEnv.get_certificate_status(domain)
        assert 'renewal' not in status
        assert 'sha256-fingerprint' in status['rsa']
        assert 'valid' in status['rsa']
        assert 'from' in status['rsa']['valid']

    # simple MD, drive it, manipulate staged credentials and check status
    def test_920_002(self):
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([domain], restart=False)
        # copy a real certificate from LE over to staging
        staged_cert = os.path.join(TestEnv.STORE_DIR, 'staging', domain, 'pubcert.pem') 
        real_cert = os.path.join('data', 'test_920', '002.pubcert')
        assert copyfile(real_cert, staged_cert)
        status = TestEnv.get_certificate_status(domain)
        # status shows the copied cert's properties as staged
        assert 'renewal' in status
        assert 'Thu, 29 Aug 2019 16:06:35 GMT' == status['renewal']['cert']['rsa']['valid']['until']
        assert 'Fri, 31 May 2019 16:06:35 GMT' == status['renewal']['cert']['rsa']['valid']['from']
        assert '03039C464D454EDE79FCD2CAE859F668F269' == status['renewal']['cert']['rsa']['serial']
        assert 'sha256-fingerprint' in status['renewal']['cert']['rsa']

    # test if switching status off has effect
    def test_920_003(self):
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_line("MDCertificateStatus off")
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([domain], restart=False)
        status = TestEnv.get_certificate_status(domain)
        assert not status

    # get the complete md-status JSON, check that it
    def test_920_004(self):
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_line("MDCertificateStatus off")
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([domain])
        status = TestEnv.get_md_status("")
        assert "version" in status
        assert "managed-domains" in status
        assert 1 == len(status["managed-domains"])

    # get the status of a domain on base server
    def test_920_010(self):
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf(std_vhosts=False, text="""
LogLevel md:trace2
LogLevel ssl:debug
                
MDBaseServer on
MDPortMap http:- https:%s

Listen %s
ServerAdmin admin@not-forbidden.org
ServerName %s
SSLEngine on
Protocols h2 http/1.1 acme-tls/1

<Location "/server-status">
    SetHandler server-status
</Location>
<Location "/md-status">
    SetHandler md-status
</Location>
            """ % (TestEnv.HTTPS_PORT, TestEnv.HTTPS_PORT, domain))
        conf.add_md(domains)
        conf.install()
        TestEnv.HTTPD_CHECK_URL = TestEnv.HTTPD_URL_SSL
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([domain], restart=False)
        status = TestEnv.get_md_status("")
        assert "version" in status
        assert "managed-domains" in status
        assert 1 == len(status["managed-domains"])
        # get the html page
        status = TestEnv.get_server_status()
        assert re.search(r'<h3>Managed Certificates</h3>', status, re.MULTILINE)
        # get the ascii summary
        status = TestEnv.get_server_status(query="?auto")
        m = re.search(r'Managed Certificates: total=(\d+), ok=(\d+) renew=(\d+) errored=(\d+) ready=(\d+)',
                      status, re.MULTILINE)
        assert 1 == int(m.group(1))
        assert 0 == int(m.group(2))
        assert 1 == int(m.group(3))
        assert 0 == int(m.group(4))
        assert 1 == int(m.group(5))

    def test_920_011(self):
        # MD with static cert files in base server, see issue #161
        domain = self.test_domain
        domains = [domain, 'www.%s' % domain]
        testpath = os.path.join(TestEnv.GEN_DIR, 'test_920_011')
        # cert that is only 10 more days valid
        TestEnv.create_self_signed_cert(domains, {"notBefore": -70, "notAfter": 20},
                                        serial=920011, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        conf = HttpdConf(std_vhosts=False, text=f"""
LogLevel md:trace2
LogLevel ssl:debug
                
MDPortMap http:- https:{TestEnv.HTTPS_PORT}

Listen {TestEnv.HTTPS_PORT}
ServerAdmin admin@not-forbidden.org
ServerName {domain}
SSLEngine on
Protocols h2 http/1.1 acme-tls/1

MDBaseServer on

<Location "/server-status">
    SetHandler server-status
</Location>
<Location "/md-status">
    SetHandler md-status
</Location>
            """)
        conf.start_md(domains)
        conf.add_line(f"MDCertificateFile {cert_file}")
        conf.add_line(f"MDCertificateKeyFile {pkey_file}")
        conf.end_md()
        conf.install()
        TestEnv.HTTPD_CHECK_URL = TestEnv.HTTPD_URL_SSL
        assert TestEnv.apache_restart() == 0
        status = TestEnv.get_md_status(domain)
        assert status
        assert 'renewal' not in status
        print(status)
        assert status['state'] == TestEnv.MD_S_COMPLETE
        assert status['renew-mode'] == 1  # manual

    # MD with 2 certificates
    def test_920_020(self):
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.add_line("MDStapling on")
        conf.add_line("MDPrivateKeys secp256r1 RSA")
        conf.add_md(domains)
        conf.add_vhost(domain)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([domain], restart=False)
        # In the stats JSON, we excpect 2 certificates under 'renewal'
        stat = TestEnv.get_md_status(domain)
        assert 'renewal' in stat
        assert 'cert' in stat['renewal']
        assert 'rsa' in stat['renewal']['cert']
        assert 'secp256r1' in stat['renewal']['cert']
        # In /.httpd/certificate-status 'renewal' we excpect 2 certificates
        status = TestEnv.get_certificate_status(domain)
        assert 'renewal' in status
        assert 'cert' in status['renewal']
        assert 'secp256r1' in status['renewal']['cert']
        assert 'rsa' in status['renewal']['cert']
        # restart and activate
        # once activated, certs are listed in status
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_md_status(domain)
        assert 'cert' in stat
        assert 'valid' in stat['cert']
        for ktype in ['rsa', 'secp256r1']:
            assert ktype in stat['cert']
            if not TestEnv.ACME_LACKS_OCSP:
                assert 'ocsp' in stat['cert'][ktype]
