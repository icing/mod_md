# test mod_md basic configurations

import re
import time
from datetime import datetime, timedelta

import pytest

from md_conf import HttpdConf
from md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestConf:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.clear_store()

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env):
        env.apache_error_log_clear()

    # test case: just one MDomain definition
    def test_300_001(self, env):
        HttpdConf(env, text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org
            """).install()
        assert env.apache_restart() == 0

    # test case: two MDomain definitions, non-overlapping
    def test_300_002(self, env):
        HttpdConf(env, text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org
            MDomain example2.org www.example2.org mail.example2.org
            """).install()
        assert env.apache_restart() == 0

    # test case: two MDomain definitions, exactly the same
    def test_300_003(self, env):
        assert env.apache_stop() == 0
        HttpdConf(env, text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            """).install()
        assert env.apache_fail() == 0
        
    # test case: two MDomain definitions, overlapping
    def test_300_004(self, env):
        assert env.apache_stop() == 0
        HttpdConf(env, text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            MDomain example2.org test3.not-forbidden.org www.example2.org mail.example2.org
            """).install()
        assert env.apache_fail() == 0

    # test case: two MDomains, one inside a virtual host
    def test_300_005(self, env):
        HttpdConf(env, text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            <VirtualHost *:12346>
                MDomain example2.org www.example2.org www.example3.org
            </VirtualHost>
            """).install()
        assert env.apache_restart() == 0

    # test case: two MDomains, one correct vhost name
    def test_300_006(self, env):
        HttpdConf(env, text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            <VirtualHost *:12346>
                ServerName example2.org
                MDomain example2.org www.example2.org www.example3.org
            </VirtualHost>
            """).install()
        assert env.apache_restart() == 0

    # test case: two MDomains, two correct vhost names
    def test_300_007(self, env):
        HttpdConf(env, text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            <VirtualHost *:12346>
                ServerName example2.org
                MDomain example2.org www.example2.org www.example3.org
            </VirtualHost>
            <VirtualHost *:12346>
                ServerName www.example2.org
            </VirtualHost>
            """).install()
        assert env.apache_restart() == 0

    # test case: two MDomains, overlapping vhosts
    def test_300_008(self, env):
        HttpdConf(env, text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            <VirtualHost *:12346>
                ServerName example2.org
                ServerAlias www.example3.org
                MDomain example2.org www.example2.org www.example3.org
            </VirtualHost>

            <VirtualHost *:12346>
                ServerName www.example2.org
                ServerAlias example2.org
            </VirtualHost>
            """).install()
        assert env.apache_restart() == 0

    # test case: vhosts with overlapping MDs
    def test_300_009(self, env):
        assert env.apache_stop() == 0
        conf = HttpdConf(env, text="""
            ServerAdmin admin@not-forbidden.org
            MDMembers manual
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            MDomain example2.org www.example2.org www.example3.org
            """)
        conf.add_ssl_vhost(port=12346, domains=["example2.org", "www.example3.org"])
        conf.add_ssl_vhost(port=12346, domains=["www.example2.org", "example2.org"])
        conf.add_ssl_vhost(port=12346, domains=["not-forbidden.org", "example2.org"])
        conf.install()
        assert env.apache_fail() == 0

    # test case: MDomain, vhost with matching ServerAlias
    def test_300_010(self, env):
        HttpdConf(env, text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org

            <VirtualHost *:12346>
                ServerName not-forbidden.org
                ServerAlias test3.not-forbidden.org
            </VirtualHost>
            """).install()
        assert env.apache_restart() == 0
        assert (0, 0) == env.httpd_error_log_count()

    # test case: MDomain, misses one ServerAlias
    def test_300_011a(self, env):
        conf = HttpdConf(env, text="""
            MDomain not-forbidden.org manual www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
        """)
        conf.add_ssl_vhost(port=env.https_port, domains=[
            "not-forbidden.org", "test3.not-forbidden.org", "test4.not-forbidden.org"
        ])
        conf.install()
        assert env.apache_fail() == 0
        assert (1, 0) == env.httpd_error_log_count(expect_errors=True)
        env.apache_error_log_clear()

    # test case: MDomain, misses one ServerAlias, but auto add enabled
    def test_300_011b(self, env):
        assert env.apache_stop() == 0
        HttpdConf(env, text="""
            MDomain not-forbidden.org auto mail.not-forbidden.org

            <VirtualHost *:%s>
                ServerName not-forbidden.org
                ServerAlias test3.not-forbidden.org
                ServerAlias test4.not-forbidden.org
            </VirtualHost>
            """ % env.https_port).install()
        assert env.apache_restart() == 0
        assert (0, 0) == env.httpd_error_log_count()

    # test case: MDomain does not match any vhost
    def test_300_012(self, env):
        HttpdConf(env, text="""
            MDomain example012.org www.example012.org
            <VirtualHost *:12346>
                ServerName not-forbidden.org
                ServerAlias test3.not-forbidden.org
            </VirtualHost>
            """).install()
        assert env.apache_restart() == 0
        assert (0, 1) == env.httpd_error_log_count(expect_errors=True)

    # test case: one md covers two vhosts
    def test_300_013(self, env):
        HttpdConf(env, text="""
            MDomain example2.org test-a.example2.org test-b.example2.org
            <VirtualHost *:12346>
                ServerName test-a.example2.org
            </VirtualHost>
            <VirtualHost *:12346>
                ServerName test-b.example2.org
            </VirtualHost>
            """).install()
        assert env.apache_restart() == 0
        assert (0, 0) == env.httpd_error_log_count()

    # test case: global server name as managed domain name
    def test_300_014(self, env):
        HttpdConf(env, text="""
            MDomain %s www.example2.org

            <VirtualHost *:12346>
                ServerName www.example2.org
            </VirtualHost>
            """ % env.domains[0]).install()
        assert env.apache_restart() == 0
        assert (0, 0) == env.httpd_error_log_count()

    # test case: valid pkey specification
    def test_300_015(self, env):
        HttpdConf(env, text="""
            MDPrivateKeys Default
            MDPrivateKeys RSA
            MDPrivateKeys RSA 2048
            MDPrivateKeys RSA 3072
            MDPrivateKeys RSA 4096
            """).install()
        assert env.apache_restart() == 0
        assert (0, 0) == env.httpd_error_log_count()

    # test case: invalid pkey specification
    @pytest.mark.parametrize("line,exp_err_msg", [
        ("MDPrivateKeys", "needs to specify the private key type"), 
        ("MDPrivateKeys Default RSA 1024", "'Default' allows no other parameter"),
        ("MDPrivateKeys RSA 1024", "must be 2048 or higher"),
        ("MDPrivateKeys RSA 1024", "must be 2048 or higher"),
        ("MDPrivateKeys rsa 2048 rsa 4096", "two keys of type 'RSA' are not possible"),
        ("MDPrivateKeys p-256 secp384r1 P-256", "two keys of type 'P-256' are not possible"),
        ])
    def test_300_016(self, env, line, exp_err_msg):
        HttpdConf(env, text=line).install()
        assert env.apache_fail() == 0
        assert exp_err_msg in env.apachectl_stderr

    # test case: invalid renew window directive
    @pytest.mark.parametrize("line,exp_err_msg", [
        ("MDRenewWindow dec-31", "has unrecognized format"), 
        ("MDRenewWindow 1y", "has unrecognized format"), 
        ("MDRenewWindow 10 d", "takes one argument"), 
        ("MDRenewWindow 102%", "a length of 100% or more is not allowed.")])
    def test_300_017(self, env, line, exp_err_msg):
        HttpdConf(env, text=line).install()
        assert env.apache_fail() == 0
        assert exp_err_msg in env.apachectl_stderr

    # test case: invalid uri for MDProxyPass
    @pytest.mark.parametrize("line,exp_err_msg", [
        ("MDHttpProxy", "takes one argument"), 
        ("MDHttpProxy localhost:8080", "scheme must be http or https"),
        ("MDHttpProxy https://127.0.0.1:-443", "invalid port"),
        ("MDHttpProxy HTTP localhost 8080", "takes one argument")])
    def test_300_018(self, env, line, exp_err_msg):
        HttpdConf(env, text=line).install()
        assert env.apache_fail() == 0, "Server accepted test config {}".format(line)
        assert exp_err_msg in env.apachectl_stderr

    # test case: invalid parameter for MDRequireHttps
    @pytest.mark.parametrize("line,exp_err_msg", [
        ("MDRequireHTTPS yes", "supported parameter values are 'temporary' and 'permanent'"),
        ("MDRequireHTTPS", "takes one argument")])
    def test_300_019(self, env, line, exp_err_msg):
        HttpdConf(env, text=line).install()
        assert env.apache_fail() == 0, "Server accepted test config {}".format(line)
        assert exp_err_msg in env.apachectl_stderr

    # test case: invalid parameter for MDMustStaple
    @pytest.mark.parametrize("line,exp_err_msg", [
        ("MDMustStaple", "takes one argument"), 
        ("MDMustStaple yes", "supported parameter values are 'on' and 'off'"),
        ("MDMustStaple true", "supported parameter values are 'on' and 'off'")])
    def test_300_020(self, env, line, exp_err_msg):
        HttpdConf(env, text=line).install()
        assert env.apache_fail() == 0, "Server accepted test config {}".format(line)
        assert exp_err_msg in env.apachectl_stderr

    # test case: alt-names incomplete detection, github isse #68
    def test_300_021(self, env):
        conf = HttpdConf(env, text="""
            MDMembers manual
            MDomain secret.com
            """)
        conf.add_ssl_vhost(port=12344, domains=[
            "not.secret.com", "secret.com"
        ])
        conf.install()
        assert env.apache_fail() == 0
        assert (1, 0) == env.httpd_error_log_count(expect_errors=True)
        assert env.httpd_error_log_scan(
            re.compile(".*Virtual Host not.secret.com:0 matches Managed Domain 'secret.com', "
                       "but the name/alias not.secret.com itself is not managed. A requested "
                       "MD certificate will not match ServerName.*"))
        env.apache_error_log_clear()

    # test case: use MDRequireHttps in an <if> construct, but not in <Directory
    def test_300_022(self, env):
        HttpdConf(env, text="""
            MDomain secret.com
            <If "1 == 1">
              MDRequireHttps temporary
            </If>
            <VirtualHost *:12344>
                ServerName secret.com
            </VirtualHost>
            """).install()
        assert env.apache_restart() == 0

    # test case: use MDRequireHttps not in <Directory
    def test_300_023(self, env):
        conf = HttpdConf(env, text="""
            MDomain secret.com
            <Directory /tmp>
              MDRequireHttps temporary
            </Directory>
            """)
        conf.add_ssl_vhost(port=12344, domains=["secret.com"])
        conf.install()
        assert env.apache_fail() == 0
        env.apache_error_log_clear()
