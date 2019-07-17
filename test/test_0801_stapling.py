# test mod_md stapling support

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


class TestStapling:

    @classmethod
    def setup_class(cls):
        print("setup_class:%s" % cls.__name__)
        TestEnv.init()
        TestEnv.clear_store()
        TestEnv.check_acme()
        cls.domain = TestEnv.get_class_domain(cls)
        cls.configure_httpd(cls.domain)
        assert TestEnv.apache_restart() == 0
        assert TestEnv.await_completion( [ cls.domain ] )
        TestEnv.check_md_complete( cls.domain )

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
    
    # MD with stapling enabled, no mod_ssl stapling
    def test_801_001(self):
        domain = TestStapling.domain
        TestStapling.configure_httpd(domain)
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_ocsp_status(domain)
        assert stat['ocsp'] == "no response sent" 
        stat = TestEnv.get_md_status(domain)
        assert not stat["stapling"]
        #
        # turn stapling on, wait for it to appear in connections
        TestStapling.configure_httpd(domain, "MDStapling on")
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.await_ocsp_status(domain)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
        stat = TestEnv.get_md_status(domain)
        assert stat["stapling"]
        assert stat["ocsp"]["status"] == "good"
        assert stat["ocsp"]["valid"]
        #
        # turn stapling off (explicitly) again, should disappear
        TestStapling.configure_httpd(domain, "MDStapling off")
        assert TestEnv.apache_restart() == 0
        stat = TestEnv.get_ocsp_status(domain)
        assert stat['ocsp'] == "no response sent" 
        stat = TestEnv.get_md_status(domain)
        assert not stat["stapling"]
        


