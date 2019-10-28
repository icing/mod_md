# test mod_md acme terms-of-service handling

import copy
import json
import os
import re
import shutil
import sys
import time
import pytest

from datetime import datetime
from shutil import copyfile
from TestEnv import TestEnv
from TestHttpdConf import HttpdConf

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
    HttpdConf().install()
    assert TestEnv.apache_stop() == 0

def teardown_module(module):
    print("teardown_module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0
        
class TestStoreMigrate:

    # install old store, start a2md list, check files afterwards
    def test_0010_000(self):
        domain = "7007-1502285564.org"
        TestEnv.replace_store(os.path.join(TestEnv.TESTROOT, "data/store_migrate/1.0/sample1"))
        #
        # use 1.0 file name for private key
        fpkey_1_0 = os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'pkey.pem')
        fpkey_1_1 = os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'privkey.pem')
        cert_1_0 = os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'cert.pem')
        cert_1_1 = os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'pubcert.pem')
        chain_1_0 = os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'chain.pem')
        #
        assert os.path.exists(fpkey_1_0)
        assert os.path.exists(cert_1_0)
        assert os.path.exists(chain_1_0)
        assert not os.path.exists(fpkey_1_1)
        assert not os.path.exists(cert_1_1)
        #
        md = TestEnv.a2md([ "-vvv", "list", domain ])['jout']['output'][0]
        assert domain == md["name"]
        #
        assert not os.path.exists(fpkey_1_0)
        assert os.path.exists(cert_1_0)
        assert os.path.exists(chain_1_0)
        assert os.path.exists(fpkey_1_1)
        assert os.path.exists(cert_1_1)
