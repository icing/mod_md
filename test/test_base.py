# test mod_md acme terms-of-service handling

import copy
import json
import pytest
import re
import os
import shutil
import socket
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

SEC_PER_DAY = 24 * 60 * 60

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
        cls.HTTP_PROXY_PORT = cls.config.get('global', 'http_proxy_port')
        cls.HTTPD_HOST = "localhost"
        cls.HTTPD_URL = "http://" + cls.HTTPD_HOST + ":" + cls.HTTP_PORT
        cls.HTTPD_URL_SSL = "https://" + cls.HTTPD_HOST + ":" + cls.HTTPS_PORT
        cls.HTTPD_PROXY_URL = "http://" + cls.HTTPD_HOST + ":" + cls.HTTP_PROXY_PORT
        cls.HTTPD_CHECK_URL = cls.HTTPD_PROXY_URL 

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
        cls.clear_store()
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
    def purge_store( cls ) : 
        print("purge store dir: %s" % TestEnv.STORE_DIR)
        assert len(TestEnv.STORE_DIR) > 1
        if os.path.exists(TestEnv.STORE_DIR):
            shutil.rmtree(TestEnv.STORE_DIR, ignore_errors=False)
        os.makedirs(TestEnv.STORE_DIR)

    @classmethod
    def clear_store( cls ) : 
        print("clear store dir: %s" % TestEnv.STORE_DIR)
        assert len(TestEnv.STORE_DIR) > 1
        if not os.path.exists(TestEnv.STORE_DIR):
            os.makedirs(TestEnv.STORE_DIR)
        for dir in [ "challenges", "tmp", "archive", "domains", "accounts", "staging" ]:
            shutil.rmtree(os.path.join(TestEnv.STORE_DIR, dir), ignore_errors=True)

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
    def path_domain( cls, domain, archiveVersion=0, staging=False ) :
        if archiveVersion == 0:
            return os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'md.json' )
        elif staging == True:
            return os.path.join( TestEnv.STORE_DIR, 'staging', domain, 'md.json' )
        else:
            return os.path.join( TestEnv.STORE_DIR, 'archive', domain + '.' + str(archiveVersion), 'md.json' )

    @classmethod
    def path_domain_pubcert( cls, domain, archiveVersion=0, staging=False ) :
        if archiveVersion == 0:
            return os.path.join(TestEnv.STORE_DIR, 'domains', domain, 'pubcert.pem')
        elif staging == True:
            return os.path.join(TestEnv.STORE_DIR, 'staging', domain, 'pubcert.pem')
        else:
            return os.path.join( TestEnv.STORE_DIR, 'archive', domain + '.' + str(archiveVersion), 'pubcert.pem')

    @classmethod
    def path_domain_privkey( cls, domain, archiveVersion=0 ) :
        if archiveVersion == 0:
            return os.path.join( TestEnv.STORE_DIR, 'domains', domain, 'privkey.pem')
        else:
            return os.path.join( TestEnv.STORE_DIR, 'archive', domain + '.' + str(archiveVersion), 'privkey.pem')

    @classmethod
    def path_fallback_cert( cls, domain ) :
        return os.path.join(TestEnv.STORE_DIR, 'domains', domain, 'fallback-cert.pem')

    @classmethod
    def replace_store( cls, src):
        shutil.rmtree(TestEnv.STORE_DIR, ignore_errors=False)
        shutil.copytree(src, TestEnv.STORE_DIR)
    
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
    def apachectl( cls, cmd, conf=None, check_live=True ) :
        if conf:
            cls.install_test_conf(conf)
        args = [cls.APACHECTL, "-d", cls.WEBROOT, "-k", cmd]
        print "execute: ", " ".join(args)
        cls.apachectl_stderr = ""
        p = subprocess.Popen(args, stderr=subprocess.PIPE)
        (output, cls.apachectl_stderr) = p.communicate()
        sys.stderr.write(cls.apachectl_stderr)
        rv = p.wait()
        if rv == 0:
            if check_live:
                rv = 0 if cls.is_live(cls.HTTPD_CHECK_URL, 5) else -1
            else:
                rv = 0 if cls.is_dead(cls.HTTPD_CHECK_URL, 5) else -1
        return rv

    @classmethod
    def apache_restart( cls ) :
        return cls.apachectl( "graceful" )
        
    @classmethod
    def apache_start( cls ) :
        return cls.apachectl( "start" )

    @classmethod
    def apache_stop( cls ) :
        return cls.apachectl( "stop", check_live=False )

    @classmethod
    def apache_fail( cls ) :
        rv = cls.apachectl( "graceful", check_live=False )
        if rv == 0:
            return -1
        else:
            print "check, if dead: " + cls.HTTPD_CHECK_URL
            return 0 if cls.is_dead(cls.HTTPD_CHECK_URL, 5) else -1
        
    @classmethod
    def apache_err_reset( cls ):
        cls.apachectl_stderr = ""
        if os.path.isfile(cls.ERROR_LOG):
            os.remove(cls.ERROR_LOG)

    RE_MD_RESET = re.compile('.*\[md:info\].*initializing\.\.\.')
    RE_MD_ERROR = re.compile('.*\[md:error\].*')
    RE_MD_WARN  = re.compile('.*\[md:warn\].*')

    @classmethod
    def apache_err_count( cls ):
        ecount = 0
        wcount = 0
        
        if cls.apachectl_stderr:
            for line in cls.apachectl_stderr.split():
                m = cls.RE_MD_ERROR.match(line)
                if m:
                    ecount += 1
                    continue
                m = cls.RE_MD_WARN.match(line)
                if m:
                    wcount += 1
                    continue
        elif os.path.isfile(cls.ERROR_LOG):
            fin = open(cls.ERROR_LOG)
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

    @classmethod
    def apache_err_total( cls ):
        ecount = 0
        wcount = 0
        
        if os.path.isfile(cls.ERROR_LOG):
            fin = open(cls.ERROR_LOG)
            for line in fin:
                m = cls.RE_MD_ERROR.match(line)
                if m:
                    ecount += 1
                    continue
                m = cls.RE_MD_WARN.match(line)
                if m:
                    wcount += 1
                    continue
        return (ecount, wcount)

    @classmethod
    def apache_err_scan( cls, regex ):
        if not os.path.isfile(cls.ERROR_LOG):
            return False
        fin = open(cls.ERROR_LOG)
        for line in fin:
            m = regex.match(line)
            if m:
                return True
        return False


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
    def getStatus(cls, domain, path, useHTTPS=True):
        result = cls.get_meta(domain, path, useHTTPS)
        return result['http_status']

    @classmethod
    def get_meta(cls, domain, path, useHTTPS=True):
        schema = "https" if useHTTPS else "http"
        port = cls.HTTPS_PORT if useHTTPS else cls.HTTP_PORT
        result = TestEnv.curl([ "-D", "-", "-k", "--resolve", ("%s:%s:127.0.0.1" % (domain, port)), 
                               ("%s://%s:%s%s" % (schema, domain, port, path)) ])
        assert result['rv'] == 0
        # read status
        m = re.match("HTTP/\\d(\\.\\d)? +(\\d\\d\\d) .*", result['stdout'])
        assert m
        result['http_status'] = int(m.group(2))
        # collect response headers
        h = {}
        for m in re.findall("^(\\S+): (.*)\r$", result['stdout'], re.M) :
            h[ m[0] ] = m[1]
        result['http_headers'] = h
        return result

    @classmethod
    def get_content(cls, domain, path, useHTTPS=True):
        schema = "https" if useHTTPS else "http"
        port = cls.HTTPS_PORT if useHTTPS else cls.HTTP_PORT
        result = TestEnv.curl([ "-k", "--resolve", ("%s:%s:127.0.0.1" % (domain, port)), 
                               ("%s://%s:%s%s" % (schema, domain, port, path)) ])
        assert result['rv'] == 0
        return result['stdout']

    @classmethod
    def await_completion(cls, names, timeout):
        try_until = time.time() + timeout
        while len(names) > 0:
            if time.time() >= try_until:
                return False
            allChanged = True
            for name in names:
                # check status in md.json
                md = TestEnv.a2md( [ "list", name ] )['jout']['output'][0]
                if md['state'] == TestEnv.MD_S_COMPLETE:
                    if 'renew' in md and md['renew'] == True:
                        # check staging area, if there's already a new cert waiting
                        path_cert_staging = TestEnv.path_domain_pubcert( name, staging=True )
                        if os.path.exists(path_cert_staging):
                            # OK (completed in staging)
                            names.remove(name)
                    else:
                        # OK (completed)
                        names.remove(name)

            if len(names) != 0:
                time.sleep(0.5)
        return True

    @classmethod
    def check_file_permissions( cls, domain ):
        md = cls.a2md([ "list", domain ])['jout']['output'][0]
        assert md
        acct = md['ca']['account']
        assert acct
        cls.check_file_access( cls.path_store_json(),                           0600 )
        # domains
        cls.check_file_access( os.path.join( cls.STORE_DIR, 'domains' ),        0700 )
        cls.check_file_access( os.path.join( cls.STORE_DIR, 'domains', domain ),0700 )
        cls.check_file_access( cls.path_domain_privkey( domain ),               0600 )
        cls.check_file_access( cls.path_domain_pubcert( domain ),               0600 )
        cls.check_file_access( cls.path_domain( domain ),                       0600 )
        # archive
        cls.check_file_access( cls.path_domain( domain, archiveVersion=1 ),     0600 )
        # accounts
        cls.check_file_access( os.path.join( cls.STORE_DIR, 'accounts' ),       0755 )
        cls.check_file_access( os.path.join( cls.STORE_DIR, 'accounts', acct ), 0755 )
        cls.check_file_access( cls.path_account( acct ),                        0644 )
        cls.check_file_access( cls.path_account_key( acct ),                    0644 )
        # staging
        cls.check_file_access( os.path.join( cls.STORE_DIR, 'staging' ),        0755 )

# -----------------------------------------------
# --
# --     dynamic httpd configuration
# --

class HttpdConf(object):
    # Utility class for creating Apache httpd test configurations

    def __init__(self, path, writeCertFiles=False, sslOnly=False, acmeUrl=None, acmeTos=None):
        self.path = path
        self.sslOnly = sslOnly
        self.writeCertFiles = writeCertFiles
        if acmeUrl == None:
            acmeUrl = TestEnv.ACME_URL
        if acmeTos == None:
            acmeTos = TestEnv.ACME_TOS
        if os.path.isfile(self.path):
            os.remove(self.path)
        open(self.path, "a").write(("  MDCertificateAuthority %s\n"
                                    "  MDCertificateProtocol ACME\n"
                                    "  MDCertificateAgreement %s\n\n")
                                   % (acmeUrl, acmeTos))

    def _add_line(self, line):
        open(self.path, "a").write(line + "\n")

    def add_drive_mode(self, mode):
        self._add_line("  MDDriveMode %s\n" % mode)

    def add_renew_window(self, window):
        self._add_line("  MDRenewWindow %s\n" % window)

    def add_private_key(self, keyType, keyParams):
        self._add_line("  MDPrivateKeys %s %s\n" % (keyType, " ".join(map(lambda p: str(p), keyParams))) )

    def add_admin(self, email):
        self._add_line("  ServerAdmin mailto:%s\n\n" % email)

    def add_md(self, dnsList):
        self._add_line("  ManagedDomain %s\n\n" % " ".join(dnsList))

    def add_must_staple(self, mode):
        self._add_line("  MDMustStaple %s\n" % mode)

    def add_ca_challenges(self, type_list):
        self._add_line("  MDCAChallenges %s\n" % " ".join(type_list))

    def add_http_proxy(self, url):
        self._add_line("  MDHttpProxy %s\n" % url)

    def add_require_ssl(self, mode):
        self._add_line("  MDRequireHttps %s\n" % mode)

    def add_vhost(self, port, name, aliasList, docRoot="htdocs", 
                  withSSL=True, certPath=None, keyPath=None):
        self.start_vhost(port, name, aliasList, docRoot, withSSL, certPath, keyPath)
        self.end_vhost()

    def start_vhost(self, port, name, aliasList, docRoot="htdocs", 
                  withSSL=True, certPath=None, keyPath=None):
        f = open(self.path, "a") 
        f.write("<VirtualHost *:%s>\n" % port)
        f.write("    ServerName %s\n" % name)
        if len(aliasList) > 0:
            for alias in aliasList:
                f.write("    ServerAlias %s\n" % alias )
        f.write("    DocumentRoot %s\n\n" % docRoot)
        if withSSL:
            f.write("    SSLEngine on\n")
            if self.writeCertFiles:
                certPath = certPath if certPath else TestEnv.path_domain_pubcert(name)
                keyPath = keyPath if keyPath else TestEnv.path_domain_privkey(name)
                f.write(("    SSLCertificateFile %s\n"
                         "    SSLCertificateKeyFile %s\n") % (certPath, keyPath))
                  
    def end_vhost(self):
        self._add_line("</VirtualHost>\n\n")

    def install(self):
        TestEnv.install_test_conf(self.path, self.sslOnly)

# -----------------------------------------------
# --
# --     certificate handling
# --

class CertUtil(object):
    # Utility class for inspecting certificates in test cases
    # Uses PyOpenSSL: https://pyopenssl.org/en/stable/index.html

    @classmethod
    def create_self_signed_cert( cls, nameList, validDays ):
        name = nameList[0]
        certFilePath = TestEnv.path_domain_pubcert(name)
        keyFilePath = TestEnv.path_domain_privkey(name)

        # create a key pair
        if os.path.exists(keyFilePath):
            key_buffer = open(keyFilePath, 'rt').read()
            k = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_buffer)
        else:
            k = OpenSSL.crypto.PKey()
            k.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)

        # create a self-signed cert
        cert = OpenSSL.crypto.X509()
        cert.get_subject().C = "DE"
        cert.get_subject().ST = "NRW"
        cert.get_subject().L = "Muenster"
        cert.get_subject().O = "greenbytes GmbH"
        cert.get_subject().CN = name
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore( validDays["notBefore"] * SEC_PER_DAY)
        cert.gmtime_adj_notAfter( validDays["notAfter"] * SEC_PER_DAY)
        cert.set_issuer(cert.get_subject())

        cert.add_extensions([ OpenSSL.crypto.X509Extension(
            b"subjectAltName", False, ", ".join( map(lambda n: "DNS:" + n, nameList) )
        ) ])
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        open(certFilePath, "wt").write(
            OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        open(keyFilePath, "wt").write(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k))

    @classmethod
    def load_server_cert( cls, hostIP, hostPort, hostName ):
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection = OpenSSL.SSL.Connection(ctx, s)
        connection.connect((hostIP, int(hostPort)))
        connection.setblocking(1)
        connection.set_tlsext_host_name(hostName)
        connection.do_handshake()
        peer_cert = connection.get_peer_certificate()
        return CertUtil( None, cert=peer_cert )


    def __init__(self, cert_path, cert=None):
        if cert_path is not None:
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
        if cert is not None:
            self.cert = cert

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

    def get_key_length(self):
        return self.cert.get_pubkey().bits()

    def get_san_list(self):
        text = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, self.cert).decode("utf-8")
        m = re.search(r"X509v3 Subject Alternative Name:\s*(.*)", text)
        sans_list = []
        if m:
            sans_list = m.group(1).split(",")

        def _strip_prefix(s): return s.split(":")[1]  if  s.strip().startswith("DNS:")  else  s.strip()
        return map(_strip_prefix, sans_list)

    def get_must_staple(self):
        text = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, self.cert).decode("utf-8")
        m = re.search(r"1.3.6.1.5.5.7.1.24:\s*\n\s*0....", text)
        return m

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
