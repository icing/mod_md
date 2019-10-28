# test mod_md basic configurations

import os.path
import re
import pytest
import subprocess
import sys
import time

from configparser import SafeConfigParser
from datetime import datetime
from TestEnv import TestEnv
from TestHttpdConf import HttpdConf

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.clear_store()
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    TestEnv.apache_stop()


class TestConf:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.httpd_error_log_clear()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # test case: just one MDomain definition
    def test_300_001(self):
        HttpdConf(text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org
            """).install()
        assert TestEnv.apache_restart() == 0

    # test case: two MDomain definitions, non-overlapping
    def test_300_002(self):
        HttpdConf(text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org
            MDomain example2.org www.example2.org mail.example2.org
            """).install()
        assert TestEnv.apache_restart() == 0

    # test case: two MDomain definitions, exactly the same
    def test_300_003(self):
        assert TestEnv.apache_stop() == 0
        HttpdConf(text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            """).install()
        assert TestEnv.apache_fail() == 0
        
    # test case: two MDomain definitions, overlapping
    def test_300_004(self):
        assert TestEnv.apache_stop() == 0
        HttpdConf(text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            MDomain example2.org test3.not-forbidden.org www.example2.org mail.example2.org
            """).install()
        assert TestEnv.apache_fail() == 0

    # test case: two MDomains, one inside a virtual host
    def test_300_005(self):
        HttpdConf(text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            <VirtualHost *:12346>
                MDomain example2.org www.example2.org www.example3.org
            </VirtualHost>
            """).install()
        assert TestEnv.apache_restart() == 0

    # test case: two MDomains, one correct vhost name
    def test_300_006(self):
        HttpdConf(text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            <VirtualHost *:12346>
                ServerName example2.org
                MDomain example2.org www.example2.org www.example3.org
            </VirtualHost>
            """).install()
        assert TestEnv.apache_restart() == 0

    # test case: two MDomains, two correct vhost names
    def test_300_007(self):
        HttpdConf(text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            <VirtualHost *:12346>
                ServerName example2.org
                MDomain example2.org www.example2.org www.example3.org
            </VirtualHost>
            <VirtualHost *:12346>
                ServerName www.example2.org
            </VirtualHost>
            """).install()
        assert TestEnv.apache_restart() == 0

    # test case: two MDomains, overlapping vhosts
    def test_300_008(self):
        HttpdConf(text="""
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
        assert TestEnv.apache_restart() == 0

    # test case: vhosts with overlapping MDs
    def test_300_009(self):
        assert TestEnv.apache_stop() == 0
        HttpdConf(text="""
            ServerAdmin admin@not-forbidden.org
            MDMembers manual
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org
            MDomain example2.org www.example2.org www.example3.org

            <VirtualHost *:12346>
                ServerName example2.org
                ServerAlias www.example3.org
                SSLEngine on
            </VirtualHost>

            <VirtualHost *:12346>
                ServerName www.example2.org
                ServerAlias example2.org
                SSLEngine on
            </VirtualHost>

            <VirtualHost *:12346>
                ServerName not-forbidden.org
                ServerAlias example2.org
                SSLEngine on
            </VirtualHost>
            """).install()
        assert TestEnv.apache_fail() == 0

    # test case: MDomain, vhost with matching ServerAlias
    def test_300_010(self):
        HttpdConf(text="""
            MDomain not-forbidden.org www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org

            <VirtualHost *:12346>
                ServerName not-forbidden.org
                ServerAlias test3.not-forbidden.org
            </VirtualHost>
            """).install()
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.httpd_error_log_count()

    # test case: MDomain, misses one ServerAlias
    def test_300_011(self):
        HttpdConf(text="""
            MDomain not-forbidden.org manual www.not-forbidden.org mail.not-forbidden.org test3.not-forbidden.org

            <VirtualHost *:%s>
                ServerName not-forbidden.org
                ServerAlias test3.not-forbidden.org
                ServerAlias test4.not-forbidden.org
                SSLEngine on
            </VirtualHost>
            """ % (TestEnv.HTTPS_PORT)).install()
        assert TestEnv.apache_fail() == 0
        assert (1, 0) == TestEnv.httpd_error_log_count()

    # test case: MDomain, misses one ServerAlias, but auto add enabled
    def test_300_011b(self):
        assert TestEnv.apache_stop() == 0
        HttpdConf(text="""
            MDomain not-forbidden.org auto mail.not-forbidden.org

            <VirtualHost *:%s>
                ServerName not-forbidden.org
                ServerAlias test3.not-forbidden.org
                ServerAlias test4.not-forbidden.org
                SSLEngine on
            </VirtualHost>
            """ % (TestEnv.HTTPS_PORT)).install()
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.httpd_error_log_count()

    # test case: MDomain does not match any vhost
    def test_300_012(self):
        HttpdConf(text="""
            MDomain example012.org www.example012.org
            <VirtualHost *:12346>
                ServerName not-forbidden.org
                ServerAlias test3.not-forbidden.org
            </VirtualHost>
            """).install()
        assert TestEnv.apache_restart() == 0
        assert (0, 1) == TestEnv.httpd_error_log_count()

    # test case: one md covers two vhosts
    def test_300_013(self):
        HttpdConf(text="""
            MDomain example2.org test-a.example2.org test-b.example2.org
            <VirtualHost *:12346>
                ServerName test-a.example2.org
            </VirtualHost>
            <VirtualHost *:12346>
                ServerName test-b.example2.org
            </VirtualHost>
            """).install()
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.httpd_error_log_count()

    # test case: global server name as managed domain name
    def test_300_014(self):
        HttpdConf(text="""
            MDomain %s www.example2.org

            <VirtualHost *:12346>
                ServerName www.example2.org
            </VirtualHost>
            """ % (TestEnv.HOSTNAME)).install()
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.httpd_error_log_count()

    # test case: valid pkey specification
    def test_300_015(self):
        HttpdConf(text="""
            MDPrivateKeys Default
            MDPrivateKeys RSA
            MDPrivateKeys RSA 2048
            MDPrivateKeys RSA 3072
            MDPrivateKeys RSA 4096
            """).install()
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.httpd_error_log_count()

    # test case: invalid pkey specification
    @pytest.mark.parametrize("line,expErrMsg", [ 
        ("MDPrivateKeys Def", "unsupported private key type"), 
        ("MDPrivateKeys", "needs to specify the private key type"), 
        ("MDPrivateKeys RSA 1024", "must be 2048 or higher"), 
        ("MDPrivateKeys RSA 2048 bla", "key type 'RSA' has only one optional parameter") ])
    def test_300_016(self, line, expErrMsg):
        HttpdConf( text=line ).install()
        assert TestEnv.apache_restart() == 1
        assert expErrMsg in TestEnv.apachectl_stderr

    # test case: invalid renew window directive
    @pytest.mark.parametrize("line,expErrMsg", [ 
        ("MDRenewWindow dec-31", "has unrecognized format"), 
        ("MDRenewWindow 1y", "has unrecognized format"), 
        ("MDRenewWindow 10 d", "takes one argument"), 
        ("MDRenewWindow 102%", "a length of 100% or more is not allowed.") ])
    def test_300_017(self, line, expErrMsg):
        HttpdConf( text=line ).install()
        assert TestEnv.apache_restart() == 1
        assert expErrMsg in TestEnv.apachectl_stderr

    # test case: invalid uri for MDProxyPass
    @pytest.mark.parametrize("line,expErrMsg", [ 
        ("MDHttpProxy", "takes one argument"), 
        ("MDHttpProxy localhost:8080", "scheme must be http or https"),
        ("MDHttpProxy https://127.0.0.1:-443", "invalid port"),
        ("MDHttpProxy HTTP localhost 8080", "takes one argument") ])
    def test_300_018(self, line, expErrMsg):
        HttpdConf( text=line ).install()
        assert TestEnv.apache_restart() == 1, "Server accepted test config {}".format(line)
        assert expErrMsg in TestEnv.apachectl_stderr

    # test case: invalid parameter for MDRequireHttps
    @pytest.mark.parametrize("line,expErrMsg", [ 
        ("MDRequireHTTPS yes", "supported parameter values are 'temporary' and 'permanent'"), 
        ("MDRequireHTTPS", "takes one argument") ])
    def test_300_019(self, line, expErrMsg):
        HttpdConf( text=line ).install()
        assert TestEnv.apache_restart() == 1, "Server accepted test config {}".format(line)
        assert expErrMsg in TestEnv.apachectl_stderr

    # test case: invalid parameter for MDMustStaple
    @pytest.mark.parametrize("line,expErrMsg", [ 
        ("MDMustStaple", "takes one argument"), 
        ("MDMustStaple yes", "supported parameter values are 'on' and 'off'"),
        ("MDMustStaple true", "supported parameter values are 'on' and 'off'") ])
    def test_300_020(self, line, expErrMsg):
        HttpdConf( text=line ).install()
        assert TestEnv.apache_restart() == 1, "Server accepted test config {}".format(line)
        assert expErrMsg in TestEnv.apachectl_stderr

    # test case: alt-names incomplete detection, github isse #68
    def test_300_021(self):
        HttpdConf(text="""
            MDMembers manual
            MDomain secret.com
            <VirtualHost *:12344>
                ServerName not.secret.com
                ServerAlias secret.com
                SSLEngine on
            </VirtualHost>
            """).install()
        assert TestEnv.apache_fail() == 0
        assert (1, 0) == TestEnv.httpd_error_log_count()
        assert TestEnv.httpd_error_log_scan( re.compile(".*Virtual Host not.secret.com:0 matches Managed Domain 'secret.com', but the name/alias not.secret.com itself is not managed. A requested MD certificate will not match ServerName.*") )

