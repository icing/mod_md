# test mod_md basic configurations

import os.path
import re
import pytest
import subprocess
import sys
import time

from ConfigParser import SafeConfigParser
from datetime import datetime
from httplib import HTTPConnection
from test_base import TestEnv

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.apache_err_reset()
    TestEnv.clear_store()
    TestEnv.APACHE_CONF_SRC = "data/test_conf_validate"
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    TestEnv.apache_stop()


class TestConf:

    def new_errors(self):
        time.sleep(.2)
        (errors, warnings) = TestEnv.apache_err_count()
        return errors
        
    def new_warnings(self):
        time.sleep(.1)
        (errors, warnings) = TestEnv.apache_err_count()
        return warnings
        
    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- tests ---------

    def test_300_001(self):
        # just one ManagedDomain definition
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_restart() == 0

    def test_300_002(self):
        # two ManagedDomain definitions, non-overlapping
        TestEnv.install_test_conf("test_002");
        assert TestEnv.apache_restart() == 0

    def test_300_003(self):
        # two ManagedDomain definitions, exactly the same
        assert TestEnv.apache_stop() == 0
        TestEnv.install_test_conf("test_003");
        assert TestEnv.apache_fail() == 0
        
    def test_300_004(self):
        # two ManagedDomain definitions, overlapping
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_stop() == 0
        TestEnv.install_test_conf("test_004");
        assert TestEnv.apache_fail() == 0

    def test_300_005(self):
        # two ManagedDomains, one inside a virtual host
        TestEnv.install_test_conf("test_005");
        assert TestEnv.apache_restart() == 0

    def test_300_006(self):
        # two ManagedDomains, one correct vhost name
        TestEnv.install_test_conf("test_006");
        assert TestEnv.apache_restart() == 0

    def test_300_007(self):
        # two ManagedDomains, two correct vhost names
        TestEnv.install_test_conf("test_007");
        assert TestEnv.apache_restart() == 0

    def test_300_008(self):
        # two ManagedDomains, overlapping vhosts
        TestEnv.install_test_conf("test_008");
        assert TestEnv.apache_restart() == 0

    def test_300_009(self):
        # vhosts with overlapping MDs
        assert TestEnv.apache_stop() == 0
        TestEnv.install_test_conf("test_009");
        assert TestEnv.apache_fail() == 0

    def test_300_010(self):
        # ManagedDomain, vhost with matching ServerAlias
        TestEnv.install_test_conf("test_010");
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.apache_err_count()

    def test_300_011(self):
        # ManagedDomain, misses one ServerAlias
        assert TestEnv.apache_stop() == 0
        TestEnv.install_test_conf("test_011");
        assert TestEnv.apache_fail() == 0
        assert (1, 0) == TestEnv.apache_err_count()

    def test_300_011b(self):
        # ManagedDomain, misses one ServerAlias, but auto add enabled
        TestEnv.install_test_conf("test_001");
        assert TestEnv.apache_stop() == 0
        TestEnv.install_test_conf("test_011b");
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.apache_err_count()

    def test_300_012(self):
        # ManagedDomain does not match any vhost
        TestEnv.install_test_conf("test_012");
        assert TestEnv.apache_restart() == 0
        assert (0, 1) == TestEnv.apache_err_count()

    def test_300_013(self):
        # one md covers two vhosts
        TestEnv.install_test_conf("test_013");
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.apache_err_count()

    def test_300_014(self):
        # global server name as managed domain name
        TestEnv.install_test_conf("test_014");
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.apache_err_count()

    def test_300_015(self):
        # valid pkey specification
        TestEnv.install_test_conf("test_015");
        assert TestEnv.apache_restart() == 0
        assert (0, 0) == TestEnv.apache_err_count()

    @pytest.mark.parametrize("confFile,expErrMsg", [ 
        ("test_016a", "unsupported private key type"), 
        ("test_016b", "needs to specify the private key type"), 
        ("test_016c", "must be 2048 or higher"), 
        ("test_016d", "key type 'RSA' has only one optinal parameter") ])
    def test_300_016(self, confFile, expErrMsg):
        # invalid pkey specification
        TestEnv.install_test_conf(confFile);
        assert TestEnv.apache_restart() == 1
        assert expErrMsg in TestEnv.apachectl_stderr

    @pytest.mark.parametrize("confFile,expErrMsg", [ 
        ("test_017a", "has unrecognized format"), 
        ("test_017b", "has unrecognized format"), 
        ("test_017c", "takes one argument"), 
        ("test_017d", "must be less than 100") ])
    def test_300_017(self, confFile, expErrMsg):
        # invalid renew window directive
        TestEnv.install_test_conf(confFile);
        assert TestEnv.apache_restart() == 1
        assert expErrMsg in TestEnv.apachectl_stderr

    @pytest.mark.parametrize("confFile,expErrMsg", [ 
        ("test_018a", "takes one argument"), 
        ("test_018b", "scheme must be http or https"),
        ("test_018c", "invalid port"),
        ("test_018d", "takes one argument") ])
    def test_300_018(self, confFile, expErrMsg):
        # invalid uri for MDProxyPass
        TestEnv.install_test_conf(confFile);
        assert TestEnv.apache_restart() == 1, "Server accepted test config {}".format(confFile)
        assert expErrMsg in TestEnv.apachectl_stderr

    @pytest.mark.parametrize("confFile,expErrMsg", [ 
        ("test_019a", "supported parameter values are 'temporary' and 'permanent'"), 
        ("test_019b", "takes one argument") ])
    def test_300_019(self, confFile, expErrMsg):
        # invalid parameter for MDRequireHttps
        TestEnv.install_test_conf(confFile);
        assert TestEnv.apache_restart() == 1, "Server accepted test config {}".format(confFile)
        assert expErrMsg in TestEnv.apachectl_stderr
