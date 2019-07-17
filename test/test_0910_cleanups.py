# test mod_md cleanups and sanitation

import json
import os
import pytest
import re
import socket
import ssl
import sys
import time

from datetime import datetime
from httplib import HTTPSConnection
from test_base import TestEnv
from test_base import HttpdConf
from test_base import CertUtil


def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    TestEnv.APACHE_CONF_SRC = "data/test_auto"
    TestEnv.check_acme()
    TestEnv.clear_store()
    TestEnv.install_test_conf()

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0

class TestCleanups:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_910_01(self):
        # generate a simple MD
        domain = self.test_domain
        domains = [ domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_drive_mode( "manual" )
        conf.add_md( domains )
        conf.add_vhost(domain)
        conf.install()

        # create valid/invalid challenges subdirs
        challenges_dir = TestEnv.store_challenges()
        dirs_before = [ "aaa", "bbb", domain, "zzz" ]
        for name in dirs_before:
            os.makedirs(os.path.join( challenges_dir, name ))

        assert TestEnv.apache_restart() == 0
        # the one we use is still there
        assert os.path.isdir(os.path.join( challenges_dir, domain ))
        # and the others are gone
        missing_after = [ "aaa", "bbb", "zzz" ]
        for name in missing_after:
            assert not os.path.exists(os.path.join( challenges_dir, name ))

