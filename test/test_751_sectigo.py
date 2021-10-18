import time

import pytest

from md_conf import HttpdConf


EABS = [
    {'kid': '0123', 'hmac': 'abcdef'},
    # add a working EAB to enable these tests
]


@pytest.mark.skipif(condition=len(EABS) == 1, reason="no Sectigo EAB added")
class TestSectigo:

    DEMO_ACME = "https://acme.demo.sectigo.com/"
    DEMO_TLD = "eissing.org"

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='eab')
        env.check_acme()
        env.clear_store()
        HttpdConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    def test_751_001(self, env):
        # valid config, expect cert with correct chain
        domain = f"test1.{self.DEMO_TLD}"
        domains = [domain]
        conf = HttpdConf(env)
        conf.start_md(domains)
        conf.add(f"MDCertificateAuthority {self.DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.add(f"MDExternalAccountBinding {EABS[1]['kid']} {EABS[1]['hmac']}")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        r = env.curl_get(f"https://{domain}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.response['status'] == 200

    def test_751_002(self, env):
        # without EAB set
        domain = f"test1.{self.DEMO_TLD}"
        domains = [domain]
        conf = HttpdConf(env)
        conf.start_md(domains)
        conf.add(f"MDCertificateAuthority {self.DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        md = env.get_md_status(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'

    def test_751_003(self, env):
        # with wrong EAB set
        domain = f"test1.{self.DEMO_TLD}"
        domains = [domain]
        conf = HttpdConf(env)
        conf.start_md(domains)
        conf.add(f"MDCertificateAuthority {self.DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.add(f"MDExternalAccountBinding xxxxxx aaaaaaaaaaaaasdddddsdasdsadsadsadasdsadsa")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        md = env.get_md_status(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:unauthorized'

    def test_751_004(self, env):
        # valid config, get cert, add dns name, renew cert
        domain = f"test1.{self.DEMO_TLD}"
        domain2 = f"test2.{self.DEMO_TLD}"
        domains = [domain]
        conf = HttpdConf(env)
        conf.start_md(domains)
        conf.add(f"MDCertificateAuthority {self.DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.add(f"MDExternalAccountBinding {EABS[1]['kid']} {EABS[1]['hmac']}")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        r = env.curl_get(f"https://{domain}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.response['status'] == 200
        r = env.curl_get(f"https://{domain2}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.exit_code != 0
        # add the domain2 to the dns names
        domains = [domain, domain2]
        conf = HttpdConf(env)
        conf.start_md(domains)
        conf.add(f"MDCertificateAuthority {self.DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.add(f"MDExternalAccountBinding {EABS[1]['kid']} {EABS[1]['hmac']}")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        r = env.curl_get(f"https://{domain2}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.response['status'] == 200

    def test_751_020(self, env):
        # valid config, get cert, check OCSP status
        domain = f"test1.{self.DEMO_TLD}"
        domains = [domain]
        conf = HttpdConf(env)
        conf.add("MDStapling on")
        conf.start_md(domains)
        conf.add(f"""
            MDCertificateAuthority {self.DEMO_ACME}
            MDCACertificateFile none
            MDExternalAccountBinding {EABS[1]['kid']} {EABS[1]['hmac']}
            """)
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        r = env.curl_get(f"https://{domain}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.response['status'] == 200
        time.sleep(1)
        for domain in domains:
            stat = env.await_ocsp_status(domain,
                                         ca_file=f"{env.test_dir}/data/sectigo-demo-root.pem")
            assert stat['ocsp'] == "successful (0x0)"
            assert stat['verify'] == "0 (ok)"

