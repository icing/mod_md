# test mod_md message support

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


class TestMessage:

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.apache_err_reset();
        TestEnv.clear_store()
        self.test_domain = TestEnv.get_method_domain(method)
        self.mcmd = ("%s/message.py" % TestEnv.TESTROOT)
        self.mlog = ("%s/message.log" % TestEnv.GEN_DIR)
        if os.path.isfile(self.mlog):
            os.remove(self.mlog)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # test: signup with configured message cmd that is invalid
    def test_901_001(self):
        domain = self.test_domain
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_message_cmd( "blablabla" )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        # this command should have failed and logged an error
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10109:"

    # test: signup with configured message cmd that is valid but returns != 0
    def test_901_002(self):
        self.mcmd = ("%s/notifail.py" % TestEnv.TESTROOT)
        domain = self.test_domain
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_message_cmd( "%s %s" % (self.mcmd, self.mlog) )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        # this command should have failed and logged an error
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10109:"

    # test: signup with working message cmd and see that it logs the right things
    def test_901_003(self):
        domain = self.test_domain
        dnsList = [ domain, "www." + domain ]
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_message_cmd( "%s %s" % (self.mcmd, self.mlog) )
        conf.add_drive_mode( "auto" )
        conf.add_md( dnsList )
        conf.add_vhost( TestEnv.HTTPS_PORT, domain, aliasList=[ dnsList[1] ])
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        # this command did not fail and logged itself the correct information
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(self.mlog).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', 'renewed', '%s']" % (self.mcmd, self.mlog, domain)) == nlines[0].strip()



    

