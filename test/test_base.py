# test mod_md acme terms-of-service handling

import copy
import json
import pytest
import re
import os
import shutil
import subprocess
import sys
import time
import OpenSSL

from datetime import datetime
from datetime import tzinfo
from datetime import timedelta
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

        cls.GEN_DIR   = cls.config.get('global', 'gen_dir')

        cls.ACME_URL_DEFAULT  = cls.config.get('acme', 'url_default')
        cls.ACME_URL  = cls.config.get('acme', 'url')
        cls.ACME_TOS  = cls.config.get('acme', 'tos')
        cls.ACME_TOS2 = cls.config.get('acme', 'tos2')
        cls.WEBROOT   = cls.config.get('global', 'server_dir')
        cls.TESTROOT   = os.path.join(cls.WEBROOT, '..', '..')

        cls.APACHECTL = os.path.join(cls.PREFIX, 'bin', 'apachectl')
        cls.ERROR_LOG = os.path.join(cls.WEBROOT, "logs", "error_log")
        cls.APACHE_CONF_DIR = os.path.join(cls.WEBROOT, "conf")
        cls.APACHE_SSL_DIR = os.path.join(cls.APACHE_CONF_DIR, "ssl")
        cls.APACHE_CONF = os.path.join(cls.APACHE_CONF_DIR, "httpd.conf")
        cls.APACHE_TEST_CONF = os.path.join(cls.APACHE_CONF_DIR, "test.conf")
        cls.APACHE_CONF_SRC = "data"
        cls.APACHE_HTDOCS_DIR = os.path.join(cls.WEBROOT, "htdocs")

        cls.HTTP_PORT = cls.config.get('global', 'http_port')
        cls.HTTPS_PORT = cls.config.get('global', 'https_port')
        cls.HTTPD_HOST = "localhost"
        cls.HTTPD_URL = "http://" + cls.HTTPD_HOST + ":" + cls.HTTP_PORT
        cls.HTTPD_URL_SSL = "https://" + cls.HTTPD_HOST + ":" + cls.HTTPS_PORT

        cls.A2MD      = cls.config.get('global', 'a2md_bin')
        cls.CURL      = cls.config.get('global', 'curl_bin')
        cls.OPENSSL   = cls.config.get('global', 'openssl_bin')

        cls.MD_S_UNKNOWN = 0
        cls.MD_S_INCOMPLETE = 1
        cls.MD_S_COMPLETE = 2
        cls.MD_S_EXPIRED = 3
        cls.MD_S_ERROR = 4

        cls.EMPTY_JOUT = { 'status' : 0, 'output' : [] }

        cls.ACME_SERVER_DOWN = False
        cls.ACME_SERVER_OK = False

        cls.set_store_dir('md')
        cls.install_test_conf()

    @classmethod
    def set_store_dir( cls, dir ) :
        cls.STORE_DIR = os.path.join(cls.WEBROOT, dir)
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
        print "stderr: ", errput
        try:
            jout = json.loads(output)
        except:
            jout = None
            print "stdout: ", output
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
    def curl( cls, args ) :
        return cls.run( [ cls.CURL ] + args )

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
                time.sleep(.2)
            except:
                print "Unexpected error:", sys.exc_info()[0]
                time.sleep(.2)
        print "Unable to contact server after %d sec" % timeout
        return False

    @classmethod
    def is_dead( cls, url, timeout ) :
        server = urlparse(url)
        try_until = time.time() + timeout
        print("checking reachability of %s" % url)
        while time.time() < try_until:
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout)
                c.request('HEAD', server.path)
                resp = c.getresponse()
                c.close()
                time.sleep(.2)
            except IOError:
                return True
            except:
                return True
        print "Server still responding after %d sec" % timeout
        return False

    @classmethod
    def get_json( cls, url, timeout ) :
        data = cls.get_plain( url, timeout )
        if data:
            return json.loads(data)
        return None

    @classmethod
    def get_plain( cls, url, timeout ) :
        server = urlparse(url)
        try_until = time.time() + timeout
        while time.time() < try_until:
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout)
                c.request('GET', server.path)
                resp = c.getresponse()
                data = resp.read()
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
    def check_acme( cls ) :
        if cls.ACME_SERVER_OK:
            return True
        if cls.ACME_SERVER_DOWN:
            pytest.skip(msg="ACME server not running")
            return False
        if cls.is_live(cls.ACME_URL, 0.5):
            cls.ACME_SERVER_OK = True
            return True
        else:
            cls.ACME_SERVER_DOWN = True
            pytest.fail(msg="ACME server not running", pytrace=False)
            return False


    # --------- access local store ---------

    @classmethod
    def clear_store( cls ) : 
        print("clear store dir: %s" % TestEnv.STORE_DIR)
        assert len(TestEnv.STORE_DIR) > 1
        if os.path.exists(TestEnv.STORE_DIR):
            shutil.rmtree(TestEnv.STORE_DIR, ignore_errors=False)
        os.makedirs(TestEnv.STORE_DIR)

    @classmethod
    def authz_save( cls, name, content ) :
        dir = os.path.join(TestEnv.STORE_DIR, 'staging', name)
        os.makedirs(dir)
        open( os.path.join( dir, 'authz.json'), "w" ).write(content)

    @classmethod
    def path_store_json( cls ) : 
        return os.path.join(TestEnv.STORE_DIR, 'md_store.json')

    @classmethod
    def path_account( cls, acct ) : 
        return os.path.join(TestEnv.STORE_DIR, 'accounts', acct, 'account.json')

    @classmethod
    def path_account_key( cls, acct ) : 
        return os.path.join(TestEnv.STORE_DIR, 'accounts', acct, 'account.pem')

    @classmethod
    def path_challenges( cls ) : 
        return os.path.join(TestEnv.STORE_DIR, 'challenges')

    @classmethod
    def path_domain( cls, domain, archiveVersion=0 ) :
        if archiveVersion == 0:
            return os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'md.json' )
        else:
            return os.path.join( TestEnv.STORE_DIR, 'archive', domain + '.' + str(archiveVersion), 'md.json' )

    @classmethod
    def path_domain_cert( cls, domain, archiveVersion=0 ) :
        if archiveVersion == 0:
            return os.path.join(TestEnv.STORE_DIR, 'domains', domain, 'cert.pem')
        else:
            return os.path.join( TestEnv.STORE_DIR, 'archive', domain + '.' + str(archiveVersion), 'cert.pem')

    @classmethod
    def path_domain_pkey( cls, domain, archiveVersion=0 ) :
        if archiveVersion == 0:
            return os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'pkey.pem')
        else:
            return os.path.join( TestEnv.STORE_DIR, 'archive', domain + '.' + str(archiveVersion), 'pkey.pem')

    @classmethod
    def path_domain_ca_chain( cls, domain, archiveVersion=0 ) :
        if archiveVersion == 0:
            return os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'chain.pem' )
        else:
            return os.path.join( TestEnv.STORE_DIR, 'archive', domain + '.' + str(archiveVersion), 'chain.pem' )

    # --------- control apache ---------

    @classmethod
    def install_test_conf( cls, conf=None, sslOnly=False) :
        if sslOnly:
            root_conf_src = os.path.join("conf", "httpd_https.conf")
        else:
            root_conf_src = os.path.join("conf", "httpd_http.conf")
        copyfile(root_conf_src, cls.APACHE_CONF)

        if conf is None:
            conf_src = os.path.join("conf", "test.conf")
        elif os.path.isabs(conf):
            conf_src = conf
        else:
            conf_src = os.path.join(cls.APACHE_CONF_SRC, conf + ".conf")
        copyfile(conf_src, cls.APACHE_TEST_CONF)

    @classmethod
    def apachectl( cls, conf, cmd ) :
        cls.install_test_conf(conf)
        args = [cls.APACHECTL, "-d", cls.WEBROOT, "-k", cmd]
        print "execute: ", " ".join(args)
        return subprocess.call(args)

    @classmethod
    def apache_restart( cls, checkWithSSL=False ) :
        args = [cls.APACHECTL, "-d", cls.WEBROOT, "-k", "graceful"]
        print "execute: ", " ".join(args)
        rv = subprocess.call(args)
        if rv == 0:
            url = cls.HTTPD_URL_SSL if checkWithSSL else cls.HTTPD_URL
            rv = 0 if cls.is_live(url, 5) else -1
        return rv
        
    @classmethod
    def apache_start( cls, checkWithSSL=False ) :
        args = [cls.APACHECTL, "-d", cls.WEBROOT, "-k", "start"]
        print "execute: ", " ".join(args)
        rv = subprocess.call(args)
        if rv == 0:
            url = cls.HTTPD_URL_SSL if checkWithSSL else cls.HTTPD_URL
            rv = 0 if cls.is_live(url, 5) else -1
        return rv

    @classmethod
    def apache_stop( cls, checkWithSSL=False ) :
        args = [cls.APACHECTL, "-d", cls.WEBROOT, "-k", "stop"]
        print "execute: ", " ".join(args)
        rv = subprocess.call(args)
        if rv == 0:
            url = cls.HTTPD_URL_SSL if checkWithSSL else cls.HTTPD_URL
            rv = 0 if cls.is_dead(url, 5) else -1
        return rv

    @classmethod
    def apache_fail( cls, checkWithSSL=False ) :
        args = [cls.APACHECTL, "-d", cls.WEBROOT, "-k", "graceful"]
        print "execute: ", " ".join(args)
        rv = subprocess.call(args)
        print "returned: ", rv
        rv = 0 if rv != 0 else -1
        if rv == 0:
            url = cls.HTTPD_URL_SSL if checkWithSSL else cls.HTTPD_URL
            print "check, if dead: " + url
            rv = 0 if cls.is_dead(url, 5) else -1
        return rv
        
    @classmethod
    def apache_err_reset( cls ):
        if os.path.isfile(cls.ERROR_LOG):
            os.remove(cls.ERROR_LOG)

    RE_MD_RESET = re.compile('.*\[md:info\].*initializing\.\.\.')
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
                    continue
                m = cls.RE_MD_WARN.match(line)
                if m:
                    wcount += 1
                    continue
                m = cls.RE_MD_RESET.match(line)
                if m:
                    ecount = 0
                    wcount = 0
            return (ecount, wcount)

    # --------- check utilities ---------

    @classmethod
    def check_json_contains(cls, actual, expected):
        # write all expected key:value bindings to a copy of the actual data ... 
        # ... assert it stays unchanged 
        testJson = copy.deepcopy(actual)
        testJson.update(expected)
        assert actual == testJson

    @classmethod
    def check_file_access(cls, path, expMask):
         actualMask = os.lstat(path).st_mode & 0777
         assert oct(actualMask) == oct(expMask)

    @classmethod
    def check_dir_empty(cls, path):
         assert os.listdir(path) == []

    @classmethod
    def hasCertAltName(cls, domain):
        p = subprocess.Popen([ cls.OPENSSL, "s_client", "-servername", domain, 
                              "-host", cls.HTTPD_HOST, "-port", cls.HTTPS_PORT], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output, errput) = p.communicate()
        rv = p.wait()
        if rv != 0:
            return FALSE

        p = subprocess.Popen([ cls.OPENSSL, "x509", "-text" ],  
                             stdin=subprocess.PIPE, 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output, errput) = p.communicate(output)
        rv = p.wait()
        if rv != 0:
            return FALSE
        return re.search("DNS:" + domain, output, re.MULTILINE) != None

    @classmethod
    def getStatus(cls, domain, path):
        auth = ("%s:%s" % (domain, cls.HTTPS_PORT))
        result = TestEnv.curl([ "-k", "--resolve", ("%s:127.0.0.1" % (auth)), 
                               "-D", "-", ("https://%s%s" % (auth, path)) ])
        assert result['rv'] == 0
        m = re.match("HTTP/\\d(\\.\\d)? +(\\d\\d\\d) .*", result['stdout'])
        assert m
        return int(m.group(2))

    @classmethod
    def getContent(cls, domain, path):
        auth = ("%s:%s" % (domain, cls.HTTPS_PORT))
        result = TestEnv.curl([ "-k", "--resolve", ("%s:127.0.0.1" % (auth)), 
                               ("https://%s%s" % (auth, path)) ])
        assert result['rv'] == 0
        return result['stdout']

# -----------------------------------------------
# --
# --     dynamic httpd configuration
# --

class HttpdConf(object):
    # Utility class for creating Apache httpd test configurations

    def __init__(self, path, writeCertFiles=False, sslOnly=False):
        self.path = path
        self.sslOnly = sslOnly
        self.writeCertFiles = writeCertFiles
        if os.path.isfile(self.path):
            os.remove(self.path)
        open(self.path, "a").write(("  MDCertificateAuthority %s\n"
                                    "  MDCertificateProtocol ACME\n"
                                    "  MDCertificateAgreement %s\n\n")
                                   % (TestEnv.ACME_URL, TestEnv.ACME_TOS))

    def add_drive_mode(self, mode):
        open(self.path, "a").write("  MDDriveMode %s\n" % mode)

    def add_admin(self, email):
        open(self.path, "a").write("  ServerAdmin mailto:%s\n\n" % email)

    def add_md(self, dnsList):
        open(self.path, "a").write("  ManagedDomain %s\n\n" % " ".join(dnsList))

    def add_ca_challenges(self, type_list):
        open(self.path, "a").write("  MDCAChallenges %s\n" % " ".join(type_list))

    def add_vhost(self, port, name, aliasList, docRoot="htdocs", 
                  withSSL=True, certPath=None, keyPath=None):
        f = open(self.path, "a") 
        f.write("<VirtualHost *:%s>\n    ServerName %s\n" % (port, name))
        if len(aliasList) > 0:
            for alias in aliasList:
                f.write("    ServerAlias %s\n" % alias )
        f.write("    DocumentRoot %s\n\n" % docRoot)
        if withSSL:
            f.write("    SSLEngine on\n")
            if self.writeCertFiles:
                certPath = certPath if certPath else TestEnv.path_domain_cert(name)
                keyPath = keyPath if keyPath else TestEnv.path_domain_pkey(name)
                f.write(("    SSLCertificateFile %s\n"
                         "    SSLCertificateKeyFile %s\n") % (certPath, keyPath))
        f.write("</VirtualHost>\n\n")

    def install(self):
        TestEnv.install_test_conf(self.path, self.sslOnly)

# -----------------------------------------------
# --
# --     certificate handling
# --

class CertUtil(object):
    # Utility class for inspecting certificates in test cases
    # Uses PyOpenSSL: https://pyopenssl.org/en/stable/index.html

    def __init__(self, cert_path):
        self.cert_path = cert_path
        # load certificate and private key
        if cert_path.startswith("http"):
            cert_data = TestEnv.get_plain(cert_path, 1)
        else:
            cert_data = CertUtil._load_binary_file(cert_path)

        for file_type in (OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1):
            try:
                self.cert = OpenSSL.crypto.load_certificate(file_type, cert_data)
            except Exception as error:
                self.error = error

        if self.cert is None:
            raise self.error

    def get_serial(self):
        return self.cert.get_serial_number()

    def get_not_before(self):
        tsp = self.cert.get_notBefore()
        return self._parse_tsp(tsp)

    def get_not_after(self):
        tsp = self.cert.get_notAfter()
        return self._parse_tsp(tsp)

    def get_cn(self):
        return self.cert.get_subject().CN

    def get_san_list(self):
        text = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, self.cert).decode("utf-8")
        m = re.search(r"X509v3 Subject Alternative Name:\s*(.*)", text)
        sans_list = []
        if m:
            sans_list = m.group(1).split(",")

        def _strip_prefix(s): return s.split(":")[1]  if  s.strip().startswith("DNS:")  else  s.strip()
        return map(_strip_prefix, sans_list)

    @classmethod
    def validate_privkey(cls, privkey_path, passphrase=None):
        privkey_data = cls._load_binary_file(privkey_path)
        privkey = None
        if passphrase:
            privkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privkey_data, passphrase)
        else:
            privkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privkey_data)
        return privkey.check()

    def validate_cert_matches_priv_key(self, privkey_path):
        # Verifies that the private key and cert match.
        privkey_data = CertUtil._load_binary_file(privkey_path)
        privkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privkey_data)
        context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        context.use_privatekey(privkey)
        context.use_certificate(self.cert)
        context.check_privatekey()

    # --------- _utils_ ---------

    def _parse_tsp(self, tsp):
        # timestampss returned by PyOpenSSL are bytes
        # parse date and time part
        tsp_reformat = [tsp[0:4], b"-", tsp[4:6], b"-", tsp[6:8], b" ", tsp[8:10], b":", tsp[10:12], b":", tsp[12:14]]
        timestamp =  datetime.strptime(b"".join(tsp_reformat), '%Y-%m-%d %H:%M:%S')
        # adjust timezone
        tz_h, tz_m = 0, 0
        m = re.match(r"([+\-]\d{2})(\d{2})", b"".join([tsp[14:]]))
        if m:
            tz_h, tz_m = int(m.group(1)),  int(m.group(2))  if  tz_h > 0  else  -1 * int(m.group(2))
        return timestamp.replace(tzinfo = self.FixedOffset(60 * tz_h + tz_m))

    @classmethod
    def _load_binary_file(cls, path):
        with open(path, mode="rb")	 as file:
            return file.read()

    class FixedOffset(tzinfo):

        def __init__(self, offset):
            self.__offset = timedelta(minutes = offset)

        def utcoffset(self, dt):
            return self.__offset

        def tzname(self, dt):
            return None

        def dst(self, dt):
            return timedelta(0)
