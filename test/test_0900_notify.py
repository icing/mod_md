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


class TestNotify:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.apache_err_reset();
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)
        self.ncmd = ("%s/notify.py" % TestEnv.TESTROOT)
        self.nlog = ("%s/notify.log" % TestEnv.GEN_DIR)
        if os.path.isfile(self.nlog):
            os.remove(self.nlog)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # test: signup with configured notify cmd that is invalid
    def test_900_001(self):
        domain = self.test_domain
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_notify_cmd( "blablabla" )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        # this command should have failed and logged an error
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10108:"

    # test: signup with configured notify cmd that is valid but returns != 0
    def test_900_002(self):
        self.ncmd = ("%s/notifail.py" % TestEnv.TESTROOT)
        domain = self.test_domain
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_notify_cmd( "%s %s" % (self.ncmd, self.nlog) )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        # this command should have failed and logged an error
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10108:"

    # test: signup with working notify cmd and see that it logs the right things
    def test_900_010(self):
        domain = self.test_domain
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_notify_cmd( "%s %s" % (self.ncmd, self.nlog) )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        # this command did not fail and logged itself the correct information
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(self.nlog).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', '%s']" % (self.ncmd, self.nlog, domain)) == nlines[0].strip()

    # test: signup with working notify cmd and see that it is called with the 
    #       configured extra arguments
    def test_900_011(self):
        domain = self.test_domain
        dnsList = [ domain, "www." + domain ]
        extra_arg = "test_900_011_extra"
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_notify_cmd( "%s %s %s" % (self.ncmd, self.nlog, extra_arg) )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        # this command did not fail and logged itself the correct information
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(self.nlog).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', '%s', '%s']" % (self.ncmd, self.nlog, extra_arg, domain)) == nlines[0].strip()

    # test: signup with working notify cmd for 2 MD and expect it to be called twice
    def test_900_012(self):
        domain1 = "a-" + self.test_domain
        dnsList1 = [ domain1, "www." + domain1 ]
        domain2 = "b-" + self.test_domain
        dnsList2 = [ domain2, "www." + domain2 ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_notify_cmd( "%s %s" % (self.ncmd, self.nlog) )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList1 )
        conf.add_md( dnsList2 )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain1, aliasList=[ dnsList1[1] ])
        conf.add_vhost( TestEnv.HTTPS_PORT, domain2, aliasList=[ dnsList2[1] ])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain1, domain2 ], restart=False )
        stat = TestEnv.get_md_status(domain1)
        assert stat["renewal"]["last"]["status"] == 0
        stat = TestEnv.get_md_status(domain2)
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(self.nlog).readlines()
        assert 2 == len(nlines)



    
