# test mod_md notify support

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
    TestEnv.install_test_conf();
    assert TestEnv.apache_start() == 0
    

def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    assert TestEnv.apache_stop() == 0


class TestAuto:

    @classmethod
    def setup_class(cls):
        time.sleep(1)
        cls.dns_uniq = "%d.org" % time.time()
        cls.TMP_CONF = os.path.join(TestEnv.GEN_DIR, "auto.conf")


    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.apache_err_reset();
        TestEnv.clear_store()
        TestEnv.install_test_conf();
        self.test_n = re.match("test_(.+)", method.__name__).group(1)
        self.test_domain =  ("%s-" % self.test_n) + TestAuto.dns_uniq

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    #-----------------------------------------------------------------------------------------------
    # MD host with notifcy command
    # 
    #-----------------------------------------------------------------------------------------------
    # test case: signup with configured notify cmd that is invalid
    #
    def test_9001(self):
        domain = ("%s-" % self.test_n) + TestAuto.dns_uniq
        
        # generate config with two MDs
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@example.org" )
        conf.add_notify_cmd( "blablabla" )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True )
        conf.install()

        # restart, and retrieve cert
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], 30 )
        # this command should have failed and logged an error
        assert (1, 0) == TestEnv.apache_err_total()

    def test_9010(self):
        domain = ("%s-" % self.test_n) + TestAuto.dns_uniq
        ncmd = ("%s/notify.py" % TestEnv.TESTROOT)
        nlog = ("%s/notify.log" % TestEnv.GEN_DIR)
        
        # generate config with two MDs
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@example.org" )
        conf.add_notify_cmd( "%s %s" % (ncmd, nlog) )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True )
        conf.install()

        # restart, and retrieve cert
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], 30 )
        # this command should have failed and logged an error
        assert (0, 0) == TestEnv.apache_err_total()
        nlines = open(nlog).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', '%s']" % (ncmd, nlog, domain)) == nlines[0]

    def test_9011(self):
        domain = ("%s-" % self.test_n) + TestAuto.dns_uniq
        ncmd = ("%s/notify.py" % TestEnv.TESTROOT)
        nlog = ("%s/notify.log" % TestEnv.GEN_DIR)
        
        # generate config with two MDs
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf( TestAuto.TMP_CONF )
        conf.add_admin( "admin@example.org" )
        conf.add_notify_cmd( "%s %s test_9011" % (ncmd, nlog) )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ], withSSL=True )
        conf.install()

        # restart, and retrieve cert
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], 30 )
        # this command should have failed and logged an error
        assert (0, 0) == TestEnv.apache_err_total()
        nlines = open(nlog).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', 'test_9011', '%s']" % (ncmd, nlog, domain)) == nlines[0]


    
