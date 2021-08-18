# test mod_md notify support

import os

import pytest

from md_conf import HttpdConf


class TestNotify:
    notify_cmd = None
    notify_log = None
    domain = None

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.check_acme()
        env.clear_store()

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        self.domain = env.get_request_domain(request)
        self.notify_cmd = ("%s/notify.py" % env.TESTROOT)
        self.notify_log = ("%s/notify.log" % env.GEN_DIR)
        if os.path.isfile(self.notify_log):
            os.remove(self.notify_log)

    def configure_httpd(self, env, domain, add_lines=""):
        conf = HttpdConf(env)
        conf.add_admin("admin@" + domain)
        conf.add_line(add_lines)
        conf.add_md([domain])
        conf.add_vhost(domain)
        conf.install()
        return domain
    
    # test: invalid notify cmd, check error
    def test_900_001(self, env):
        command = "blablabla"
        args = ""
        self.configure_httpd(env, self.domain, """
            MDNotifyCmd %s %s
            """ % (command, args))
        assert env.apache_restart() == 0
        assert env.await_completion([self.domain], restart=False)
        stat = env.get_md_status(self.domain)
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10108:"

    # test: valid notify cmd that fails, check error
    def test_900_002(self, env):
        command = "%s/notifail.py" % env.TESTROOT
        args = ""
        self.configure_httpd(env, self.domain, """
            MDNotifyCmd %s %s
            """ % (command, args))
        assert env.apache_restart() == 0
        assert env.await_completion([self.domain], restart=False)
        stat = env.get_md_status(self.domain)
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10108:"

    # test: valid notify that logs to file
    def test_900_010(self, env):
        command = self.notify_cmd
        args = self.notify_log
        self.configure_httpd(env, self.domain, """
            MDNotifyCmd %s %s
            """ % (command, args))
        assert env.apache_restart() == 0
        assert env.await_completion([self.domain], restart=False)
        stat = env.get_md_status(self.domain)
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(self.notify_log).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', '%s']" % (command, args, self.domain)) == nlines[0].strip()

    # test: signup with working notify cmd and see that it is called with the 
    #       configured extra arguments
    def test_900_011(self, env):
        command = self.notify_cmd
        args = self.notify_log
        extra_arg = "test_900_011_extra"
        self.configure_httpd(env, self.domain, """
            MDNotifyCmd %s %s %s
            """ % (command, args, extra_arg))
        assert env.apache_restart() == 0
        assert env.await_completion([self.domain], restart=False)
        stat = env.get_md_status(self.domain)
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(self.notify_log).readlines()
        assert ("['%s', '%s', '%s', '%s']" % (command, args, extra_arg, self.domain)) == nlines[0].strip()

    # test: signup with working notify cmd for 2 MD and expect it to be called twice
    def test_900_012(self, env):
        md1 = "a-" + self.domain
        domains1 = [md1, "www." + md1]
        md2 = "b-" + self.domain
        domains2 = [md2, "www." + md2]
        command = self.notify_cmd
        args = self.notify_log
        conf = HttpdConf(env)
        conf.add_admin("admin@not-forbidden.org")
        conf.add_notify_cmd("%s %s" % (command, args))
        conf.add_md(domains1)
        conf.add_md(domains2)
        conf.add_vhost(domains1)
        conf.add_vhost(domains2)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([md1, md2], restart=False)
        stat = env.get_md_status(md1)
        assert stat["renewal"]["last"]["status"] == 0
        stat = env.get_md_status(md2)
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(args).readlines()
        assert 2 == len(nlines)
