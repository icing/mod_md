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
from test_base import TestEnv
from test_base import HttpdConf
from test_base import CertUtil


class TestNotify:

    @classmethod
    def setup_class(cls):
        print("setup_class:%s" % cls.__name__)
        TestEnv.init()
        TestEnv.clear_store()
        TestEnv.check_acme()
        cls.domain = TestEnv.get_class_domain(cls)
        cls.notify_cmd = ("%s/notify.py" % TestEnv.TESTROOT)
        cls.notify_log = ("%s/notify.log" % TestEnv.GEN_DIR)

    @classmethod
    def teardown_class(cls):
        print("teardown_class:%s" % cls.__name__)
        assert TestEnv.apache_stop() == 0
    
    @classmethod
    def configure_httpd(cls, domain, add_lines=""):
        cls.domain = domain 
        conf = HttpdConf()
        conf.add_admin( "admin@" + domain )
        conf.add_line( add_lines )
        conf.add_md([ domain ])
        conf.add_vhost(domain)
        conf.install()
        return domain
    
    def setup_method(self, method):
        TestNotify.domain = TestEnv.get_method_domain(method)
        if os.path.isfile(TestNotify.notify_log):
            os.remove(TestNotify.notify_log)

    # test: invalid notify cmd, check error
    def test_900_001(self):
        domain = TestNotify.domain
        command = "blablabla"
        args = ""
        TestNotify.configure_httpd(domain, """
            MDNotifyCmd %s %s
            """ % (command, args))
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10108:"

    # test: valid notify cmd that fails, check error
    def test_900_002(self):
        domain = TestNotify.domain
        command = "%s/notifail.py" % (TestEnv.TESTROOT) 
        args = ""
        TestNotify.configure_httpd(domain, """
            MDNotifyCmd %s %s
            """ % (command, args))
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        assert stat["renewal"]["last"]["problem"] == "urn:org:apache:httpd:log:AH10108:"

    # test: valid notify that logs to file
    def test_900_010(self):
        domain = TestNotify.domain
        command = TestNotify.notify_cmd
        args = TestNotify.notify_log
        TestNotify.configure_httpd(domain, """
            MDNotifyCmd %s %s
            """ % (command, args))
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(TestNotify.notify_log).readlines()
        assert 1 == len(nlines)
        assert ("['%s', '%s', '%s']" % (command, args, domain)) == nlines[0].strip()

    # test: signup with working notify cmd and see that it is called with the 
    #       configured extra arguments
    def test_900_011(self):
        domain = TestNotify.domain
        command = TestNotify.notify_cmd
        args = TestNotify.notify_log
        extra_arg = "test_900_011_extra"
        TestNotify.configure_httpd(domain, """
            MDNotifyCmd %s %s %s
            """ % (command, args, extra_arg))
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ domain ], restart=False )
        stat = TestEnv.get_md_status(domain)
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(TestNotify.notify_log).readlines()
        assert ("['%s', '%s', '%s', '%s']" % (command, args, extra_arg, domain)) == nlines[0].strip()

    # test: signup with working notify cmd for 2 MD and expect it to be called twice
    def test_900_012(self):
        md1 = "a-" + TestNotify.domain
        domains1 = [ md1, "www." + md1 ]
        md2 = "b-" + TestNotify.domain
        domains2 = [ md2, "www." + md2 ]
        command = TestNotify.notify_cmd
        args = TestNotify.notify_log
        conf = HttpdConf()
        conf.add_admin( "admin@not-forbidden.org" )
        conf.add_notify_cmd( "%s %s" % (command, args) )
        conf.add_md( domains1 )
        conf.add_md( domains2 )
        conf.add_vhost(domains1)
        conf.add_vhost(domains2)
        conf.install()
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ md1, md2 ], restart=False )
        stat = TestEnv.get_md_status(md1)
        assert stat["renewal"]["last"]["status"] == 0
        stat = TestEnv.get_md_status(md2)
        assert stat["renewal"]["last"]["status"] == 0
        nlines = open(args).readlines()
        assert 2 == len(nlines)

