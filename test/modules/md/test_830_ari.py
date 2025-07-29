import logging
import time
from datetime import datetime, timedelta, timezone
import os

import pytest

from .md_env import MDTestEnv
from .md_conf import MDConf


log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
@pytest.mark.skipif(condition=not MDTestEnv.is_pebble(), reason="we beed pebble here")
class TestARI:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        env.APACHE_CONF_SRC = "data/test_auto"
        acme.start(config='default')
        env.check_acme()
        env.clear_store()
        MDConf(env).install()
        env.httpd_error_log.clear_log()
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    def _write_res_file(self, doc_root, name, content):
        if not os.path.exists(doc_root):
            os.makedirs(doc_root)
        open(os.path.join(doc_root, name), "w").write(content)

    # create a MD, check that status has an 'ari-cert-id',
    # check that ACME server gives us renewalInfo about the cert
    # check that we can set the renewalInfo to be what we want
    def test_md_830_001_ari_basic(self, env, acme):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        # restart and wait for cert
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        # restart to activate
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.get_md_status(domain)
        assert 'rsa' in stat['cert'], f'{stat}'
        assert 'ari-cert-id' in stat['cert']['rsa'], f'{stat}'
        ari_cert_id = stat['cert']['rsa']['ari-cert-id']
        ari = acme.get_ari_for(ari_cert_id)
        assert ari
        assert 'suggestedWindow' in ari
        set_ari = {
            'message': 'big, bad wolf'
        }
        r = acme.set_ari_for(domain, set_ari)
        assert r.exit_code == 0
        nari = acme.get_ari_for(ari_cert_id)
        assert nari
        assert nari == set_ari, f'{nari}'
        # we control this cert's destiny now
        ari_start: datetime = datetime.now() + timedelta(days=-1)
        ari_end: datetime = datetime.now() + timedelta(days=1)
        set_ari = {
            'suggestedWindow': {
                'start': self.ts_iso(ari_start),
                'end': self.ts_iso(ari_end),
            },
        }
        r = acme.set_ari_for(domain, set_ari)
        assert r.exit_code == 0
        # restart to trigger ARI check right away
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        # expect the domain to be renewed
        if not env.await_completion([domain]):
            env.httpd_error_log.dump(log)
            assert False, 'renewal did not happen'

    # create a MD, get certificate. Set ARI to renew seconds later with explanation,
    # check that it reacts
    def test_md_830_002_ari_trigger(self, env, acme):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        # restart and wait for cert
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        # restart to activate
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        stat = env.get_md_status(domain)
        assert 'rsa' in stat['cert'], f'{stat}'
        assert 'ari-cert-id' in stat['cert']['rsa'], f'{stat}'
        ari_cert_id = stat['cert']['rsa']['ari-cert-id']
        ari_start: datetime = datetime.now() + timedelta(seconds=3)
        ari_end: datetime = datetime.now() + timedelta(seconds=3)
        set_ari = {
            'suggestedWindow': {
                'start': self.ts_iso(ari_start),
                'end': self.ts_iso(ari_end),
            },
            'explanationURL': f'https://ari.{env.http_tld}/please-renew-now'
        }
        r = acme.set_ari_for(domain, set_ari)
        assert r.exit_code == 0
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        # expect the domain to be renewed
        if not env.await_completion([domain]):
            env.httpd_error_log.dump(log)
            assert False, 'renewal did not happen'

    # create a MD with ARI disabled. Set ARIm should have not effect.
    def test_md_830_003_ari_disabled(self, env, acme):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.add('MDRenewViaARI off')
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        # restart and wait for cert
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        # set an ARI that would trigger renewal
        ari_start: datetime = datetime.now() + timedelta(minutes=-30)
        ari_end: datetime = datetime.now() + timedelta()
        set_ari = {
            'suggestedWindow': {
                'start': self.ts_iso(ari_start),
                'end': self.ts_iso(ari_end),
            },
            'explanationURL': f'https://ari.{env.http_tld}/please-renew-now'
        }
        r = acme.set_ari_for(domain, set_ari)
        assert r.exit_code == 0
        # restart to activate cert, should not trigger ARI renewal
        assert env.apache_restart() == 0, f'{env.apachectl_stderr}'
        # expect the domain NOT to be renewed
        time.sleep(1)
        stat = env.get_md_status(domain)
        assert stat
        assert 'renewal' not in stat, f'unexpected renewal: {stat}'

    def ts_iso(self, d: datetime) -> str:
        d = d.astimezone(tz=timezone.utc)
        return d.isoformat(timespec='seconds')