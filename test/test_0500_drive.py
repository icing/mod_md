# test driving the ACME protocol

import os.path
import re
import sys
import time

from datetime import datetime
from testbase import TestEnv

def setup_module(module):
    print("setup_module: %s" % module.__name__)
    TestEnv.init()
    assert TestEnv.is_live(TestEnv.ACME_URL, 1)
    TestEnv.apache_err_reset()
    TestEnv.APACHE_CONF_SRC = "test_drive_data"
    status = TestEnv.apachectl("test1.example.org", "start")
    
def teardown_module(module):
    print("teardown_module:%s" % module.__name__)
    #status = TestEnv.apachectl(None, "stop")


class TestDrive :

    def setup_class( cls ):
        cls.dns_uniq = "%d.org" % time.time()
        
    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.clear_store()

    def test_001(self):
        # setup an md without contact, drive it
        domain = "test1." + TestDrive.dns_uniq
        assert TestEnv.a2md( [ "add", domain ] )['rv'] == 0
        run = TestEnv.a2md( [ "drive", domain ] )
        assert run['rv'] == 1
        assert re.search("no contact information", run["stderr"])

    def test_002(self):
        # setup an md with contact, drive it
        domain = "test1." + TestDrive.dns_uniq
        assert TestEnv.a2md( [ "add", domain ] )['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", domain, "contacts", "admin@test1.example.org" ] 
            )['rv'] == 0
        run = TestEnv.a2md( [ "drive", domain ] )
        assert run['rv'] == 1
        assert re.search("need to accept terms-of-service", run["stderr"])

    def test_003(self):
        # setup an md with contact and agreement, drive it
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 1)
        domain = "test003." + TestDrive.dns_uniq
        assert TestEnv.a2md( [ "add", domain ] )['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", domain, "contacts", "admin@" + domain ] 
            )['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", domain, "agreement", TestEnv.ACME_TOS ] 
            )['rv'] == 0
        run = TestEnv.a2md( [ "-vvvv", "drive", domain ] )
        print run["stderr"]
        assert run['rv'] == 0

    def test_004(self):
        # drive an md with 2 domains
        domain = "test004." + TestDrive.dns_uniq
        assert TestEnv.a2md( [ "-vvvvv", "add", domain , "www." + domain ] )['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", domain, "contacts", "admin@" + domain ] 
            )['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", domain, "agreement", TestEnv.ACME_TOS ] 
            )['rv'] == 0
        run = TestEnv.a2md( [ "-vvvv", "drive", domain ] )
        print run["stderr"]
        assert run['rv'] == 0

        
 


