# test mod_md basic configurations

import os

from TestEnv import TestEnv
from TestHttpdConf import HttpdConf


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.initv1()
    TestEnv.APACHE_CONF_SRC = "data/test_roundtrip"
    TestEnv.clear_store()
    HttpdConf().install()
    

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestRoundtripv1:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.check_acme()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add to store ---------

    def test_600_000(self):
        # test case: generate config with md -> restart -> drive -> generate config
        # with vhost and ssl -> restart -> check HTTPS access
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = HttpdConf()
        conf.add_admin("admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md(domains)
        conf.install()
        # - restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(domains)
        # - drive
        assert TestEnv.a2md(["-vvvv", "drive", domain])['rv'] == 0
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)
        # - append vhost to config
        conf.add_vhost(domains)
        conf.install()
        assert TestEnv.apache_restart() == 0
        # check: SSL is running OK
        cert = TestEnv.get_cert(domain)
        assert domain in cert.get_san_list()

        # check file system permissions:
        TestEnv.check_file_permissions(domain)

    def test_600_001(self):
        # test case: same as test_600_000, but with two parallel managed domains
        domain_a = "a-" + self.test_domain
        domain_b = "b-" + self.test_domain
        domains_a = [domain_a, "www." + domain_a]
        domains_b = [domain_b, "www." + domain_b]
        conf = HttpdConf()
        conf.add_admin("admin@not-forbidden.org")
        conf.add_drive_mode("manual")
        conf.add_md(domains_a)
        conf.add_md(domains_b)
        conf.install()

        # - restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(domains_a)
        TestEnv.check_md(domains_b)

        # - drive
        assert TestEnv.a2md(["drive", domain_a])['rv'] == 0
        assert TestEnv.a2md(["drive", domain_b])['rv'] == 0
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain_a)
        TestEnv.check_md_complete(domain_b)

        # - append vhost to config
        conf.add_vhost(domains_a)
        conf.add_vhost(domains_b)
        conf.install()

        # check: SSL is running OK
        assert TestEnv.apache_restart() == 0
        cert_a = TestEnv.get_cert(domain_a)
        assert domains_a == cert_a.get_san_list()
        cert_b = TestEnv.get_cert(domain_b)
        assert domains_b == cert_b.get_san_list()

    def test_600_002(self):
        # test case: one md, that covers two vhosts
        domain = self.test_domain
        name_a = "a-" + domain
        name_b = "b-" + domain
        domains = [domain, name_a, name_b]
        conf = HttpdConf()
        conf.add_admin("admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md(domains)
        conf.install()
        
        # - restart, check that md is in store
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md(domains)

        # - drive
        assert TestEnv.a2md(["drive", domain])['rv'] == 0
        assert TestEnv.apache_restart() == 0
        TestEnv.check_md_complete(domain)

        # - append vhost to config
        conf.add_vhost(name_a, doc_root="htdocs/a")
        conf.add_vhost(name_b, doc_root="htdocs/b")
        conf.install()
        
        # - create docRoot folder
        self._write_res_file(os.path.join(TestEnv.APACHE_HTDOCS_DIR, "a"), "name.txt", name_a)
        self._write_res_file(os.path.join(TestEnv.APACHE_HTDOCS_DIR, "b"), "name.txt", name_b)

        # check: SSL is running OK
        assert TestEnv.apache_restart() == 0
        cert_a = TestEnv.get_cert(name_a)
        assert name_a in cert_a.get_san_list()
        cert_b = TestEnv.get_cert(name_b)
        assert name_b in cert_b.get_san_list()
        assert cert_a.get_serial() == cert_b.get_serial()
        assert TestEnv.get_content(name_a, "/name.txt") == name_a
        assert TestEnv.get_content(name_b, "/name.txt") == name_b

    # --------- _utils_ ---------

    def _write_res_file(self, doc_root, name, content):
        if not os.path.exists(doc_root):
            os.makedirs(doc_root)
        open(os.path.join(doc_root, name), "w").write(content)
