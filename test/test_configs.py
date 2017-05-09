# test mod_md basic configurations

import os.path
import re
import subprocess
import time

from shutil import copyfile
from ConfigParser import SafeConfigParser

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

APACHECTL = os.path.join(PREFIX, 'bin', 'apachectl')

WEBROOT = config.get('global', 'server_dir')
ERROR_LOG = os.path.join(WEBROOT, "logs", "error_log")
TEST_CONF = os.path.join(WEBROOT, "conf", "test.conf")

RE_MD_ERROR = re.compile('.*\[md:error\].*')

def remove_if_exists(f):
    if os.path.isfile(f):
        os.remove(f)
        
def reset_errors():
    remove_if_exists(ERROR_LOG)

def count_errors():
    if not os.path.isfile(ERROR_LOG):
        return 0
    fin = open(ERROR_LOG)
    ecount = 0
    for line in fin:
        m = RE_MD_ERROR.match(line)
        if m:
            ecount += 1
    return ecount
    

def apachectl(conf, cmd):
    conf_src = os.path.join(WEBROOT, "conf", conf + ".conf")
    copyfile(conf_src, TEST_CONF)
    return subprocess.call([APACHECTL, "-d", WEBROOT, "-f", TEST_CONF, "-k", cmd])

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    reset_errors()
    status = apachectl("httpd", "start")
    assert status == 0
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    status = apachectl("httpd", "stop")


class TestConf:

    def setup_method(self, method):
        self.errors = count_errors()
                            
    def test_001(self):
        # just one ManagedDomain definition
        status = apachectl("test_001", "graceful")
        assert status == 0

    def test_002(self):
        # two ManagedDomain definitions, non-overlapping
        status = apachectl("test_002", "graceful")
        assert status == 0

    def test_003(self):
        # two ManagedDomain definitions, exactly the same
        status = apachectl("httpd", "stop")
        status = apachectl("test_003", "start")
        assert status == 0
        time.sleep(.5)
        errors = count_errors()
        # error can be reported in more than one process
        assert (errors - self.errors) == 1
        
    def test_004(self):
        # two ManagedDomain definitions, overlapping
        status = apachectl("httpd", "stop")
        status = apachectl("test_004", "start")
        assert status == 0
        time.sleep(.5)
        errors = count_errors()
        # error can be reported in more than one process
        assert (errors - self.errors) == 1

    def test_005(self):
        # two ManagedDomain, one inside a virtual host
        status = apachectl("httpd", "stop")
        status = apachectl("test_005", "start")
        assert status == 0
        time.sleep(.5)
        errors = count_errors()
        # error can be reported in more than one process
        assert (errors - self.errors) == 0
