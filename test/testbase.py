# test mod_md acme terms-of-service handling

import os
import shutil
import subprocess
import re
import sys
import time
import json

from ConfigParser import SafeConfigParser
from httplib import HTTPConnection
from shutil import copyfile
from urlparse import urlparse


class TestEnv:

    @classmethod
    def init( cls ) :
        cls.config = SafeConfigParser()
        cls.config.read('test.ini')
        cls.PREFIX = cls.config.get('global', 'prefix')

        cls.ACME_URL  = cls.config.get('acme', 'url')
        cls.ACME_TOS  = cls.config.get('acme', 'tos')
        cls.ACME_TOS2 = cls.config.get('acme', 'tos2')
        cls.WEBROOT   = cls.config.get('global', 'server_dir')
        cls.STORE_DIR = os.path.join(cls.WEBROOT, 'md')
        cls.TESTROOT   = os.path.join(cls.WEBROOT, '..', '..')

        cls.APACHECTL = os.path.join(cls.PREFIX, 'bin', 'apachectl')
        cls.ERROR_LOG = os.path.join(cls.WEBROOT, "logs", "error_log")
        cls.APACHE_TEST_CONF = os.path.join(cls.WEBROOT, "conf", "test.conf")
        cls.APACHE_CONF_SRC = "data"

        cls.HTTP_PORT = cls.config.get('global', 'http_port')
        cls.HTTPS_PORT = cls.config.get('global', 'https_port')
        cls.HTTPD_HOST = "localhost"
        cls.HTTPD_URL = "http://" + cls.HTTPD_HOST + ":" + cls.HTTP_PORT

        cls.A2MD      = cls.config.get('global', 'a2md_bin')
        cls.a2md_stdargs([cls.A2MD, "-a", cls.ACME_URL, "-d", cls.STORE_DIR, "-j" ])
        cls.a2md_rawargs([cls.A2MD, "-a", cls.ACME_URL, "-d", cls.STORE_DIR ])

    # --------- cmd execution ---------

    _a2md_args = []
    _a2md_args_raw = []
    
    @classmethod
    def run( cls, args ) :
        print "execute: ", " ".join(args)
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output, errput) = p.communicate()
        rv = p.wait()
        # print "stderr: ", errput
        # print "stdout: ", output
        try:
            jout = json.loads(output)
        except:
            jout = None
        return { 
            "rv": rv, 
            "stdout": output, 
            "stderr": errput,
            "jout" : jout 
        }

    @classmethod
    def a2md_stdargs( cls, args ) :
        cls._a2md_args = [] + args 

    @classmethod
    def a2md_rawargs( cls, args ) :
        cls._a2md_args_raw = [] + args
         
    @classmethod
    def a2md( cls, args, raw=False ) :
        preargs = cls._a2md_args
        if raw :
            preargs = cls._a2md_args_raw
        return cls.run( preargs + args )

    # --------- HTTP ---------

    @classmethod
    def is_live( cls, url, timeout ) :
        server = urlparse(url)
        try_until = time.time() + timeout
        print("checking reachability of %s" % url)
        while time.time() < try_until:
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout)
                c.request('HEAD', server.path)
                resp = c.getresponse()
                c.close()
                return True
            except IOError:
                print "connect error:", sys.exc_info()[0]
                time.sleep(.1)
            except:
                print "Unexpected error:", sys.exc_info()[0]
        print "Unable to contact server after %d sec" % timeout
        return False

    @classmethod
    def get_json( cls, url, timeout ) :
        server = urlparse(url)
        try_until = time.time() + timeout
        while time.time() < try_until:
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout)
                c.request('GET', server.path)
                resp = c.getresponse()
                data = json.loads(resp.read())
                c.close()
                return data
            except IOError:
                print "connect error:", sys.exc_info()[0]
                time.sleep(.1)
            except:
                print "Unexpected error:", sys.exc_info()[0]
        print "Unable to contact server after %d sec" % timeout
        return None

    # --------- access local store ---------

    @classmethod
    def clear_store( cls ) : 
        print("clear store dir: %s" % TestEnv.STORE_DIR)
        assert len(TestEnv.STORE_DIR) > 1
        shutil.rmtree(TestEnv.STORE_DIR, ignore_errors=True)
        os.makedirs(TestEnv.STORE_DIR)

    @classmethod
    def path_account( cls, acct ) : 
        return TestEnv.STORE_DIR + "/accounts/" + acct + "/account.json"

    @classmethod
    def path_account_key( cls, acct ) : 
        return TestEnv.STORE_DIR + "/accounts/" + acct + "/account.key"

    @classmethod
    def path_domain_authz( cls, domain ) : 
        return TestEnv.STORE_DIR + "/domains/" + domain + "/authz.json"

    @classmethod
    def path_domain_cert( cls, domain ) : 
        return TestEnv.STORE_DIR + "/domains/" + domain + "/cert.pem"

    @classmethod
    def path_domain_pkey( cls, domain ) : 
        return TestEnv.STORE_DIR + "/domains/" + domain + "/pkey.pem"

    # --------- control apache ---------

    @classmethod
    def apachectl( cls, conf, cmd ) :
        if conf is None:
            conf_src = os.path.join("conf", "test.conf")
        else:
            conf_src = os.path.join(cls.APACHE_CONF_SRC, conf + ".conf")
        copyfile(conf_src, cls.APACHE_TEST_CONF)
        return subprocess.call([cls.APACHECTL, "-d", cls.WEBROOT, "-k", cmd])

    @classmethod
    def apache_err_reset( cls ):
        if os.path.isfile(cls.ERROR_LOG):
            os.remove(cls.ERROR_LOG)

    RE_MD_ERROR = re.compile('.*\[md:error\].*')
    RE_MD_WARN  = re.compile('.*\[md:warn\].*')

    @classmethod
    def apache_err_count( cls ):
        if not os.path.isfile(cls.ERROR_LOG):
            return (0, 0)
        else:
            fin = open(cls.ERROR_LOG)
            ecount = 0
            wcount = 0
            for line in fin:
                m = cls.RE_MD_ERROR.match(line)
                if m:
                    ecount += 1
                m = cls.RE_MD_WARN.match(line)
                if m:
                    wcount += 1
            return (ecount, wcount)

