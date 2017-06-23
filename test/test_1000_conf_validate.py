# test mod_md basic configurations

import os.path
import re
import subprocess
import sys
import time

from ConfigParser import SafeConfigParser
from datetime import datetime
from httplib import HTTPConnection
from testbase import TestEnv

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.apache_err_reset()
    TestEnv.APACHE_CONF_SRC = "data/conf_validate"
    status = TestEnv.apachectl(None, "start")
    assert status == 0
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    status = TestEnv.apachectl(None, "stop")


class TestConf:

    def new_errors(self):
        time.sleep(.1)
        (errors, warnings) = TestEnv.apache_err_count()
        return errors - self.errors
        
    def new_warnings(self):
        time.sleep(.1)
        (errors, warnings) = TestEnv.apache_err_count()
        return warnings - self.warnings
        
    def setup_method(self, method):
        time.sleep(.1)
        print("setup_method: %s" % method.__name__)
        (self.errors, self.warnings) = TestEnv.apache_err_count()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- tests ---------

    def test_001(self):
        # just one ManagedDomain definition
        assert TestEnv.apachectl("test_001", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)

    def test_002(self):
        # two ManagedDomain definitions, non-overlapping
        assert TestEnv.apachectl("test_002", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)

    def test_003(self):
        # two ManagedDomain definitions, exactly the same
        assert TestEnv.apachectl("test_003", "graceful") == 0
        assert self.new_errors() == 1
        
    def test_004(self):
        # two ManagedDomain definitions, overlapping
        assert TestEnv.apachectl("test_004", "graceful") == 0
        assert self.new_errors() == 1

    def test_005(self):
        # two ManagedDomains, one inside a virtual host
        assert TestEnv.apachectl("test_005", "graceful") == 0
        assert self.new_errors() == 0

    def test_006(self):
        # two ManagedDomains, one correct vhost name
        assert TestEnv.apachectl("test_006", "graceful") == 0
        assert self.new_errors() == 0

    def test_007(self):
        # two ManagedDomains, two correct vhost names
        assert TestEnv.apachectl("test_007", "graceful") == 0
        assert self.new_errors() == 0

    def test_008(self):
        # two ManagedDomains, overlapping vhosts
        assert TestEnv.apachectl("test_008", "graceful") == 0
        assert self.new_errors() == 0

    def test_009(self):
        # vhosts with overlapping MDs
        assert TestEnv.apachectl("test_009", "graceful") == 0
        assert self.new_errors() == 3

    def test_010(self):
        # ManagedDomain, vhost with matching ServerAlias
        assert TestEnv.apachectl("test_010", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        assert self.new_errors() == 0
        assert self.new_warnings() == 0

    def test_011(self):
        # ManagedDomain, misses one ServerAlias
        assert TestEnv.apachectl("test_011", "graceful") == 0
        assert self.new_errors() == 1
        assert self.new_warnings() == 0

    def test_012(self):
        # ManagedDomain does not match any vhost
        assert TestEnv.apachectl("test_012", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        assert self.new_errors() == 0
        assert self.new_warnings() == 3
