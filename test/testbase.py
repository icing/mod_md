# test mod_md acme terms-of-service handling

import os
import shutil
import subprocess
import sys
import time
import json

from ConfigParser import SafeConfigParser
from httplib import HTTPConnection
from urlparse import urlparse


class TestEnv:

    _a2md_args = []
    _a2md_args_raw = []
    
    @classmethod
    def init( cls ) :
        cls.config = SafeConfigParser()
        cls.config.read('test.ini')
        cls.PREFIX = cls.config.get('global', 'prefix')

        cls.A2MD      = cls.config.get('global', 'a2md_bin')
        cls.ACME_URL  = cls.config.get('acme', 'url')
        cls.ACME_TOS  = cls.config.get('acme', 'tos')
        cls.ACME_TOS2 = cls.config.get('acme', 'tos2')
        cls.WEBROOT   = cls.config.get('global', 'server_dir')
        cls.STORE_DIR = os.path.join(cls.WEBROOT, 'md')

        cls.a2md_stdargs([cls.A2MD, "-a", cls.ACME_URL, "-d", cls.STORE_DIR, "-j" ])
        cls.a2md_rawargs([cls.A2MD, "-a", cls.ACME_URL, "-d", cls.STORE_DIR ])
    
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

    @classmethod
    def clear_store( cls ) : 
        print("clear store dir: %s" % TestEnv.STORE_DIR)
        assert len(TestEnv.STORE_DIR) > 1
        shutil.rmtree(TestEnv.STORE_DIR, ignore_errors=True)
        os.makedirs(TestEnv.STORE_DIR)


