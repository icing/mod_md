# test mod_md basic configurations

import os.path
import re
import subprocess
import sys
import time

from ConfigParser import SafeConfigParser
from datetime import datetime
from httplib import HTTPConnection
from shutil import copyfile

config = SafeConfigParser()
config.read('test.ini')
PREFIX = config.get('global', 'prefix')

APACHECTL = os.path.join(PREFIX, 'bin', 'apachectl')

WEBROOT = config.get('global', 'server_dir')
ERROR_LOG = os.path.join(WEBROOT, "logs", "error_log")
TEST_CONF = os.path.join(WEBROOT, "conf", "test.conf")

HTTP_PORT = config.get('global', 'http_port')
HTTPS_PORT = config.get('global', 'https_port')


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
    if conf is None:
        conf_src = os.path.join("conf", "test.conf")
    else:
        conf_src = os.path.join("test_configs_data", conf + ".conf")
    copyfile(conf_src, TEST_CONF)
    return subprocess.call([APACHECTL, "-d", WEBROOT, "-k", cmd])

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    reset_errors()
    status = apachectl(None, "start")
    assert status == 0
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    status = apachectl(None, "stop")


def check_live(timeout):
    try_until = time.time() + timeout
    while time.time() < try_until:
        try:
            c = HTTPConnection('localhost', HTTP_PORT, timeout=timeout)
            c.request('HEAD', '/')
            resp = c.getresponse()
            print "response %d %s" % (resp.status, resp.reason)
            c.close()
            return True
        except IOError:
            print "connect error:", sys.exc_info()[0]
            time.sleep(.1)
        except:
            print "Unexpected error:", sys.exc_info()[0]
    print "Unable to contact server after %d sec" % timeout
    return False

class TestConf:

    def setup_method(self, method):
        self.errors = count_errors()
                            
    def test_001(self):
        # just one ManagedDomain definition
        assert apachectl("test_001", "graceful") == 0
        assert check_live(1)

    def test_002(self):
        # two ManagedDomain definitions, non-overlapping
        assert apachectl("test_002", "graceful") == 0
        assert check_live(1)

    def test_003(self):
        # two ManagedDomain definitions, exactly the same
        assert apachectl("test_003", "graceful") == 0
        assert not check_live(.5)
        assert (count_errors() - self.errors) == 1
        
    def test_004(self):
        # two ManagedDomain definitions, overlapping
        assert apachectl("test_004", "graceful") == 0
        assert not check_live(.5)
        assert (count_errors() - self.errors) == 1

    def test_005(self):
        # two ManagedDomain, one inside a virtual host
        assert apachectl("test_005", "graceful") == 0
        assert check_live(1)
        assert (count_errors() - self.errors) == 0
