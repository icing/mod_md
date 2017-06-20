# test mod_md basic configurations

import os.path
import pytest
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
    TestEnv.APACHE_CONF_SRC = "test_configs_data"
    status = TestEnv.apachectl(None, "start")
    assert status == 0
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    status = TestEnv.apachectl(None, "stop")


class TestConf:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        (self.errors, self.warnings) = TestEnv.apache_err_count()
        TestEnv.clear_store()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # --------- add to store ---------

    @pytest.mark.parametrize("confFile,dnsLists", [
        ("test_001", [["example.org", "www.example.org", "mail.example.org"]]),
        ("test_002", [["example.org", "www.example.org", "mail.example.org"], ["example2.org", "www.example2.org", "mail.example2.org"]])
    ])
    def test_001(self, confFile, dnsLists):
        # just one ManagedDomain definition
        assert TestEnv.apachectl(confFile, "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        for i in range (0, len(dnsLists)):
            self._check_md(dnsLists[i][0], dnsLists[i], 1)

    # --------- _utils_ ---------

    def _new_errors(self):
        (errors, warnings) = TestEnv.apache_err_count()
        return errors - self.errors

    def _new_warnings(self):
        (errors, warnings) = TestEnv.apache_err_count()
        return warnings - self.warnings

    def _check_md(self, name, dnsList, state):
        jout = TestEnv.a2md(["list"])['jout']
        assert jout
        output = jout['output']
        mdFound = False
        for i in range (0, len(output)):
            md = output[i]
            if name == md['name']:
                mdFound = True
                assert md['domains'] == dnsList
                assert md['state'] == state
        assert mdFound == True