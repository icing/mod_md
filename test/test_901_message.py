# test mod_md message support

import json
import os
import time
import pytest

from md_conf import HttpdConf
from md_env import MDTestEnv


class TestMessage:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.APACHE_CONF_SRC = "data/test_auto"
        env.check_acme()
        env.clear_store()
        HttpdConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)
        self.mcmd = ("%s/message.py" % env.TESTROOT)
        self.mcmdfail = ("%s/notifail.py" % env.TESTROOT)
        self.mlog = ("%s/message.log" % env.GEN_DIR)
        if os.path.isfile(self.mlog):
            os.remove(self.mlog)

    # test: signup with configured message cmd that is invalid
    def test_901_001(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_message_cmd("blablabla")
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        env.apache_errors_check()
        env.apache_error_log_clear()
        assert env.apache_restart() == 0
        assert env.await_file(env.store_staged_file(domain, 'job.json'))
        stat = env.get_md_status(domain)
        # this command should have failed and logged an error
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10109:"
        env.apache_error_log_clear()

    # test: signup with configured message cmd that is valid but returns != 0
    def test_901_002(self, env):
        self.mcmd = ("%s/notifail.py" % env.TESTROOT)
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_message_cmd("%s %s" % (self.mcmd, self.mlog))
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        env.apache_errors_check()
        env.apache_error_log_clear()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False)
        stat = env.get_md_status(domain)
        # this command should have failed and logged an error
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10109:"
        env.apache_error_log_clear()

    # test: signup with working message cmd and see that it logs the right things
    def test_901_003(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_message_cmd("%s %s" % (self.mcmd, self.mlog))
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False)
        stat = env.get_md_status(domain)
        # this command did not fail and logged itself the correct information
        assert stat["renewal"]["last"]["status"] == 0
        assert stat["renewal"]["log"]["entries"]
        assert stat["renewal"]["log"]["entries"][0]["type"] == "message-renewed"
        # shut down server to make sure that md has completed 
        assert env.apache_stop() == 0
        nlines = open(self.mlog).readlines()
        assert 3 == len(nlines)
        nlines = [s.strip() for s in nlines]
        assert "['{cmd}', '{logfile}', 'challenge-setup:http-01:{dns}', '{mdomain}']".format(
            cmd=self.mcmd, logfile=self.mlog, mdomain=domain, dns=domains[0]) in nlines
        assert "['{cmd}', '{logfile}', 'challenge-setup:http-01:{dns}', '{mdomain}']".format(
            cmd=self.mcmd, logfile=self.mlog, mdomain=domain, dns=domains[1]) in nlines
        assert nlines[2].strip() == "['{cmd}', '{logfile}', 'renewed', '{mdomain}']".format(
            cmd=self.mcmd, logfile=self.mlog, mdomain=domain)

    # test issue #145: 
    # - a server renews a valid certificate and is not restarted when recommended
    # - the job did not clear its next_run and was run over and over again
    # - the job logged the re-verifications again and again. which was saved.
    # - this eventually flushed out the "message-renew" log entry
    # - which caused the renew message handling to trigger again and again
    # the fix does:
    # - reset the next run
    # - no longer adds the re-validations to the log
    # - messages only once
    @pytest.mark.skipif(MDTestEnv.is_pebble(), reason="ACME server certs valid too long")
    def test_901_004(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        # force renew
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_message_cmd("%s %s" % (self.mcmd, self.mlog))
        conf.add_line("MDRenewWindow 120d")
        conf.add_line("MDActivationDelay -7d")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain], restart=False)
        env.get_md_status(domain)
        assert env.await_file(self.mlog)
        nlines = open(self.mlog).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', 'renewed', '%s']" % (self.mcmd, self.mlog, domain)) == nlines[0].strip()
    
    def test_901_010(self, env):
        # MD with static cert files, lifetime in renewal window, no message about renewal
        domain = self.test_domain
        domains = [domain, 'www.%s' % domain]
        testpath = os.path.join(env.GEN_DIR, 'test_901_010')
        # cert that is only 10 more days valid
        env.create_self_signed_cert(domains, {"notBefore": -70, "notAfter": 20},
                                    serial=901010, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_message_cmd("%s %s" % (self.mcmd, self.mlog))
        conf.start_md(domains)
        conf.add_line("MDCertificateFile %s" % cert_file)
        conf.add_line("MDCertificateKeyFile %s" % pkey_file)
        conf.end_md()
        conf.add_vhost(domain)
        conf.install()
        assert env.apache_restart() == 0
        assert not os.path.isfile(self.mlog)
        
    def test_901_011(self, env):
        # MD with static cert files, lifetime in warn window, check message
        domain = self.test_domain
        domains = [domain, 'www.%s' % domain]
        testpath = os.path.join(env.GEN_DIR, 'test_901_011')
        # cert that is only 10 more days valid
        env.create_self_signed_cert(domains, {"notBefore": -85, "notAfter": 5},
                                    serial=901011, path=testpath)
        cert_file = os.path.join(testpath, 'pubcert.pem')
        pkey_file = os.path.join(testpath, 'privkey.pem')
        assert os.path.exists(cert_file)
        assert os.path.exists(pkey_file)
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_message_cmd("%s %s" % (self.mcmd, self.mlog))
        conf.start_md(domains)
        conf.add_line("MDCertificateFile %s" % cert_file)
        conf.add_line("MDCertificateKeyFile %s" % pkey_file)
        conf.end_md()
        conf.add_vhost(domain)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_file(self.mlog)
        nlines = open(self.mlog).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', 'expiring', '%s']" % (self.mcmd, self.mlog, domain)) == nlines[0].strip()
        # check that we do not get it resend right away again
        assert env.apache_restart() == 0
        time.sleep(1)
        nlines = open(self.mlog).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', 'expiring', '%s']" % (self.mcmd, self.mlog, domain)) == nlines[0].strip()

    # MD, check messages from stapling
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_901_020(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_message_cmd("%s %s" % (self.mcmd, self.mlog))
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.add_line("MDStapling on")
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        env.await_ocsp_status(domain)
        assert env.await_file(self.mlog)
        time.sleep(1)
        nlines = open(self.mlog).readlines()
        assert 4 == len(nlines)
        assert nlines[0].strip() == ("['%s', '%s', 'challenge-setup:http-01:%s', '%s']"
                                     % (self.mcmd, self.mlog, domain, domain))
        assert nlines[1].strip() == ("['%s', '%s', 'renewed', '%s']" % (self.mcmd, self.mlog, domain))
        assert nlines[2].strip() == ("['%s', '%s', 'installed', '%s']" % (self.mcmd, self.mlog, domain))
        assert nlines[3].strip() == ("['%s', '%s', 'ocsp-renewed', '%s']" % (self.mcmd, self.mlog, domain))

    # test: while testing gh issue #146, it was noted that a failed renew notification never
    # resets the MD activity.
    @pytest.mark.skipif(MDTestEnv.is_pebble(), reason="ACME server certs valid too long")
    def test_901_030(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        # set the warn window that triggers right away and a failing message command
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_message_cmd("%s %s" % (self.mcmdfail, self.mlog))
        conf.add_md(domains)
        conf.add_line("""
            MDWarnWindow 100d
            """)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        env.get_md_status(domain)
        # this command should have failed and logged an error
        # shut down server to make sure that md has completed
        assert env.await_file(env.store_staged_file(domain, 'job.json'))
        while True:
            with open(env.store_staged_file(domain, 'job.json')) as f:
                job = json.load(f)
                if job["errors"] > 0:
                    assert job["errors"] > 0,  "unexpected job result: {0}".format(job)
                    assert job["last"]["problem"] == "urn:org:apache:httpd:log:AH10109:"
                    break
            time.sleep(0.1)

        # reconfigure to a working notification command and restart
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_message_cmd("%s %s" % (self.mcmd, self.mlog))
        conf.add_md(domains)
        conf.add_line("""
            MDWarnWindow 100d
            """)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_file(self.mlog)
        # we see the notification logged by the command
        nlines = open(self.mlog).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', 'expiring', '%s']" % (self.mcmd, self.mlog, domain)) == nlines[0].strip()
        # the error needs to be gone
        assert env.await_file(env.store_staged_file(domain, 'job.json'))
        with open(env.store_staged_file(domain, 'job.json')) as f:
            job = json.load(f)
            assert job["errors"] == 0
