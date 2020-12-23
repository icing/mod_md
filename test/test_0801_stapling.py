# test mod_md stapling support

import os
import time
import pytest

from TestEnv import TestEnv
from TestHttpdConf import HttpdConf


@pytest.mark.skipif(TestEnv.ACME_LACKS_OCSP, reason="no OCSP responder")
class TestStapling:
    domain = None
    mdA = None
    mdB = None

    @classmethod
    def setup_class(cls):
        print("setup_class:%s" % cls.__name__)
        TestEnv.init()
        TestEnv.clear_store()
        TestEnv.check_acme()
        cls.domain = TestEnv.get_class_domain(cls)
        cls.mdA = "a-" + cls.domain
        cls.mdB = "b-" + cls.domain
        cls.configure_httpd([cls.mdA, cls.mdB]).install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion([cls.mdA, cls.mdB])
        TestEnv.check_md_complete(cls.mdA)
        TestEnv.check_md_complete(cls.mdB)

    @classmethod
    def teardown_class(cls):
        print("teardown_class:%s" % cls.__name__)
        assert TestEnv.apache_stop() == 0
    
    @classmethod
    def configure_httpd(cls, domains=None, add_lines="", ssl_stapling=False):
        if not isinstance(domains, list):
            domains = [domains] if domains else []
        conf = HttpdConf()
        conf.add_admin("admin@" + cls.domain)
        if ssl_stapling:
            conf.add_line("""
                LogLevel ssl:trace2
                SSLUseStapling On
                SSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\"
                """)
        conf.add_line(add_lines)
        for domain in domains:
            conf.add_md([domain])
            conf.add_vhost(domain)
        return conf
    
    # MD with stapling on/off and mod_ssl stapling off
    # expect to only see stapling response when MD stapling is on
    def test_801_001(self):
        md = TestStapling.mdA
        TestStapling.configure_httpd(md).install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_ocsp_status(md)
        assert stat['ocsp'] == "no response sent" 
        stat = TestEnv.get_md_status(md)
        assert not stat["stapling"]
        #
        # turn stapling on, wait for it to appear in connections
        TestStapling.configure_httpd(md, """
            MDStapling on
            LogLevel md:trace5
            """).install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        stat = TestEnv.get_md_status(md)
        assert stat["stapling"]
        pkey = 'rsa'
        assert stat["cert"][pkey]["ocsp"]["status"] == "good"
        assert stat["cert"][pkey]["ocsp"]["valid"]
        #
        # turn stapling off (explicitly) again, should disappear
        TestStapling.configure_httpd(md, "MDStapling off").install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_ocsp_status(md)
        assert stat['ocsp'] == "no response sent" 
        stat = TestEnv.get_md_status(md)
        assert not stat["stapling"]
        
    # MD with stapling on/off and mod_ssl stapling on
    # expect to see stapling response in all cases
    def test_801_002(self):
        md = TestStapling.mdA
        TestStapling.configure_httpd(md, ssl_stapling=True).install()
        assert TestEnv.apache_stop() == 0
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        stat = TestEnv.get_md_status(md)
        assert not stat["stapling"]
        #
        # turn stapling on, wait for it to appear in connections
        TestStapling.configure_httpd(md, "MDStapling on", ssl_stapling=True).install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        stat = TestEnv.get_md_status(md)
        assert stat["stapling"]
        pkey = 'rsa'
        assert stat["cert"][pkey]["ocsp"]["status"] == "good"
        assert stat["cert"][pkey]["ocsp"]["valid"]
        #
        # turn stapling off (explicitly) again, should disappear
        TestStapling.configure_httpd(md, "MDStapling off", ssl_stapling=True).install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        stat = TestEnv.get_md_status(md)
        assert not stat["stapling"]
        
    # 2 MDs, one with md stapling on, one with default (off)
    def test_801_003(self):
        md_a = TestStapling.mdA
        md_b = TestStapling.mdB
        conf = TestStapling.configure_httpd()
        conf.add_line("""
            <MDomain %s>
                MDStapling on
            </MDomain>
            <MDomain %s>
            </MDomain>
            """ % (md_a, md_b))
        conf.add_vhost(md_a)
        conf.add_vhost(md_b)
        conf.install()
        assert TestEnv.apache_stop() == 0
        assert TestEnv.apache_restart() == 0
        # mdA has stapling
        stat = TestEnv.await_ocsp_status(md_a)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        stat = TestEnv.get_md_status(md_a)
        assert stat["stapling"]
        pkey = 'rsa'
        assert stat["cert"][pkey]["ocsp"]["status"] == "good"
        assert stat["cert"][pkey]["ocsp"]["valid"]
        # mdB has no stapling
        stat = TestEnv.get_ocsp_status(md_b)
        assert stat['ocsp'] == "no response sent" 
        stat = TestEnv.get_md_status(md_b)
        assert not stat["stapling"]

    # 2 MDs, md stapling on+off, ssl stapling on
    def test_801_004(self):
        md_a = TestStapling.mdA
        md_b = TestStapling.mdB
        conf = TestStapling.configure_httpd(ssl_stapling=True)
        conf.add_line("""
            <MDomain %s>
                MDStapling on
            </MDomain>
            <MDomain %s>
            </MDomain>
            """ % (md_a, md_b))
        conf.add_vhost(md_a)
        conf.add_vhost(md_b)
        conf.install()
        assert TestEnv.apache_stop() == 0
        assert TestEnv.apache_restart() == 0
        # mdA has stapling
        stat = TestEnv.await_ocsp_status(md_a)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        stat = TestEnv.get_md_status(md_a)
        assert stat["stapling"]
        pkey = 'rsa'
        assert stat["cert"][pkey]["ocsp"]["status"] == "good"
        assert stat["cert"][pkey]["ocsp"]["valid"]
        # mdB has no md stapling, but mod_ssl kicks in
        stat = TestEnv.get_ocsp_status(md_b)
        assert stat['ocsp'] == "successful (0x0)" 
        stat = TestEnv.get_md_status(md_b)
        assert not stat["stapling"]

    # MD, check that restart leaves response unchanged, reconfigure keep interval, 
    # should remove the file on restart and get a new one
    def test_801_005(self):
        # TODO: mod_watchdog seems to have problems sometimes with fast restarts
        # stopping first works.
        assert TestEnv.apache_stop() == 0
        # turn stapling on, wait for it to appear in connections
        md = TestStapling.mdA
        TestStapling.configure_httpd(md, "MDStapling on").install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        # fine the file where the ocsp response is stored
        dirpath = os.path.join(TestEnv.STORE_DIR, 'ocsp', md)
        files = os.listdir(dirpath)
        ocsp_file = None
        for name in files:
            if name.startswith("ocsp-"):
                ocsp_file = os.path.join(dirpath, name)
        assert ocsp_file
        mtime1 = os.path.getmtime(ocsp_file)
        # wait a sec, restart and check that file does not change
        time.sleep(1)
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        mtime2 = os.path.getmtime(ocsp_file)
        assert mtime1 == mtime2
        # configure a keep time of 1 second, restart, the file is gone
        # (which is a side effec that we load it before the cleanup removes it.
        #  since it was valid, no new one needed fetching
        TestStapling.configure_httpd(md, """
            MDStapling on
            MDStaplingKeepResponse 1s
            """).install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)"
        assert not os.path.exists(ocsp_file)
        # if we restart again, a new file needs to appear
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)"
        mtime3 = os.path.getmtime(ocsp_file)
        assert mtime1 != mtime3

    # MD, check that stapling renew window works. Set a large window
    # that causes response to be retrieved all the time.
    def test_801_006(self):
        assert TestEnv.apache_stop() == 0
        # turn stapling on, wait for it to appear in connections
        md = TestStapling.mdA
        TestStapling.configure_httpd(md, "MDStapling on").install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        # fine the file where the ocsp response is stored
        dirpath = os.path.join(TestEnv.STORE_DIR, 'ocsp', md)
        files = os.listdir(dirpath)
        ocsp_file = None
        for name in files:
            if name.startswith("ocsp-"):
                ocsp_file = os.path.join(dirpath, name)
        assert ocsp_file
        mtime1 = os.path.getmtime(ocsp_file)
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        # wait a sec, restart and check that file does not change
        time.sleep(1)
        mtime2 = os.path.getmtime(ocsp_file)
        assert mtime1 == mtime2
        # configure a renew window of 10 days, restart, larger than any life time.
        TestStapling.configure_httpd(md, """
            MDStapling on
            MDStaplingRenewWindow 10d
            """).install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)"
        # wait a sec, restart and check that file does change
        time.sleep(1)
        mtime3 = os.path.getmtime(ocsp_file)
        assert mtime1 != mtime3

    # MD, make a MDomain with static files, check that stapling works
    def test_801_007(self):
        assert TestEnv.apache_stop() == 0
        # turn stapling on, wait for it to appear in connections
        md = TestStapling.mdA
        conf = TestStapling.configure_httpd()
        conf.add_line("""
            <MDomain %s>
                MDCertificateKeyFile %s
                MDCertificateFile %s
                MDStapling on
            </MDomain>
            """ % (md, TestEnv.store_domain_file(md, 'privkey.pem'),
                   TestEnv.store_domain_file(md, 'pubcert.pem')))
        conf.add_vhost(md)
        conf.install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        # fine the file where the ocsp response is stored
        dirpath = os.path.join(TestEnv.STORE_DIR, 'ocsp', md)
        files = os.listdir(dirpath)
        ocsp_file = None
        for name in files:
            if name.startswith("ocsp-"):
                ocsp_file = os.path.join(dirpath, name)
        assert ocsp_file

    # Use certificate files in old skool mod_ssl set, check that stapling works
    def test_801_008(self):
        assert TestEnv.apache_stop() == 0
        # turn stapling on, wait for it to appear in connections
        md = TestStapling.mdA
        conf = TestStapling.configure_httpd()
        conf.add_line("MDStapling on")
        conf.start_vhost(md)
        conf.add_line("""
            SSLCertificateKeyFile %s
            SSLCertificateFile %s
            """ % (TestEnv.store_domain_file(md, 'privkey.pem'),
                   TestEnv.store_domain_file(md, 'pubcert.pem')))
        conf.end_vhost()
        conf.install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(md)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        # fine the file where the ocsp response is stored
        dirpath = os.path.join(TestEnv.STORE_DIR, 'ocsp', 'other')
        files = os.listdir(dirpath)
        ocsp_file = None
        for name in files:
            if name.startswith("ocsp-"):
                ocsp_file = os.path.join(dirpath, name)
        assert ocsp_file

    # Turn on stapling for a certificate without OCSP responder and issuer
    # (certificates without issuer prevent mod_ssl asking around for stapling)
    def test_801_009(self):
        assert TestEnv.apache_stop() == 0
        md = TestStapling.mdA
        domains = [md]
        testpath = os.path.join(TestEnv.GEN_DIR, 'test_801_009')
        # cert that is 30 more days valid
        TestEnv.create_self_signed_cert(domains, {"notBefore": -60, "notAfter": 30},
                                        serial=801009, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.start_md(domains)
        conf.add_line("MDCertificateFile %s" % cert_file)
        conf.add_line("MDCertificateKeyFile %s" % pkey_file)
        conf.add_line("MDStapling on")
        conf.end_md()
        conf.add_vhost(md)
        conf.install()
        assert TestEnv.apache_restart() == 0
        time.sleep(1)
        stat = TestEnv.get_ocsp_status(md)
        assert stat['ocsp'] == "no response sent" 

    # Turn on stapling for an MDomain not used in any virtualhost
    # There was a crash in server-status in this case
    def test_801_010(self):
        assert TestEnv.apache_stop() == 0
        TestEnv.clear_ocsp_store()
        md = TestStapling.mdA
        domains = [md]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.start_md(domains)
        conf.add_line("MDStapling on")
        conf.end_md()
        conf.install()
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_server_status()
        assert stat
