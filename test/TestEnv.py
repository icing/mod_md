###################################################################################################
# md end-to-end test environment class
#
# (c) 2019 greenbytes GmbH
###################################################################################################

import copy
import inspect
import json
import pytest
import re
import os
import shutil
import subprocess
import sys
import time

from datetime import datetime
from configparser import ConfigParser
from http.client import HTTPConnection
from typing import Dict
from urllib.parse import urlparse

from TestCertUtil import CertUtil


class TestEnv:
    STORE_DIR = None

    config = ConfigParser()
    config.read(os.path.join(os.path.dirname(inspect.getfile(CertUtil)), 'test.ini'))
    PREFIX = config.get('global', 'prefix')

    GEN_DIR = config.get('global', 'gen_dir')

    WEBROOT = config.get('global', 'server_dir')
    HOSTNAME = config.get('global', 'server_name')
    TESTROOT = os.path.join(WEBROOT, '..', '..')

    APACHECTL = os.path.join(PREFIX, 'bin', 'apachectl')
    APXS = os.path.join(PREFIX, 'bin', 'apxs')
    ERROR_LOG = os.path.join(WEBROOT, "logs", "error_log")
    APACHE_CONF_DIR = os.path.join(WEBROOT, "conf")
    APACHE_TEST_CONF = os.path.join(APACHE_CONF_DIR, "test.conf")
    APACHE_SSL_DIR = os.path.join(APACHE_CONF_DIR, "ssl")
    APACHE_CONF = os.path.join(APACHE_CONF_DIR, "httpd.conf")
    APACHE_CONF_SRC = "data"
    APACHE_HTDOCS_DIR = os.path.join(WEBROOT, "htdocs")

    HTTP_PORT = config.get('global', 'http_port')
    HTTPS_PORT = config.get('global', 'https_port')
    HTTP_PROXY_PORT = config.get('global', 'http_proxy_port')
    HTTPD_HOST = "localhost"
    HTTPD_URL = "http://" + HTTPD_HOST + ":" + HTTP_PORT
    HTTPD_URL_SSL = "https://" + HTTPD_HOST + ":" + HTTPS_PORT
    HTTPD_PROXY_URL = "http://" + HTTPD_HOST + ":" + HTTP_PROXY_PORT
    HTTPD_CHECK_URL = HTTPD_URL

    ACME_URL_DEFAULT = config.get('acme', 'url_default')
    ACME_URL = config.get('acme', 'url')
    ACME_TOS = config.get('acme', 'tos')
    ACME_SERVER = config.get('acme', 'server').strip()
    ACME_LACKS_OCSP = (ACME_SERVER == 'pebble')
    ACME_SERVER_DOWN = False
    ACME_SERVER_OK = False

    TEST_CA_PEM = "gen/apache/test-ca.pem"

    A2MD = config.get('global', 'a2md_bin')
    CURL = config.get('global', 'curl_bin')
    OPENSSL = config.get('global', 'openssl_bin')

    MD_S_UNKNOWN = 0
    MD_S_INCOMPLETE = 1
    MD_S_COMPLETE = 2
    MD_S_EXPIRED = 3
    MD_S_ERROR = 4

    EMPTY_JOUT = {'status': 0, 'output': []}

    DOMAIN_SUFFIX = "%d.org" % time.time()

    apachectl_stderr = None

    @classmethod
    def init(cls):
        cls.set_store_dir_default()
        cls.clear_store()

    @classmethod
    def set_store_dir(cls, dirpath):
        cls.STORE_DIR = os.path.join(cls.WEBROOT, dirpath)
        if cls.ACME_URL:
            cls.a2md_stdargs([cls.A2MD, "-a", cls.ACME_URL, "-d", cls.STORE_DIR,  "-C", cls.TEST_CA_PEM, "-j"])
            cls.a2md_rawargs([cls.A2MD, "-a", cls.ACME_URL, "-d", cls.STORE_DIR,  "-C", cls.TEST_CA_PEM])

    @classmethod
    def set_store_dir_default(cls):
        dirpath = "md"
        if cls.httpd_is_at_least("2.5.0"):
            dirpath = os.path.join("state", dirpath)
        cls.set_store_dir(dirpath)

    @classmethod
    def get_method_domain(cls, method):
        return "%s-%s" % (re.sub(r'[_]', '-', method.__name__.lower()), TestEnv.DOMAIN_SUFFIX)

    @classmethod
    def get_module_domain(cls, module):
        return "%s-%s" % (re.sub(r'[_]', '-', module.__name__.lower()), TestEnv.DOMAIN_SUFFIX)

    @classmethod
    def get_class_domain(cls, c):
        return "%s-%s" % (re.sub(r'[_]', '-', c.__name__.lower()), TestEnv.DOMAIN_SUFFIX)

    # --------- cmd execution ---------

    _a2md_args = []
    _a2md_args_raw = []

    @classmethod
    def run(cls, args, _input=None):
        p = subprocess.run(args, capture_output=True, text=True)
        # noinspection PyBroadException
        try:
            jout = json.loads(p.stdout)
        except:
            jout = None
            print("stderr: ", p.stderr)
            print("stdout: ", p.stdout)
        return {
            "rv": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "jout": jout
        }

    @classmethod
    def a2md_stdargs(cls, args):
        cls._a2md_args = [] + args

    @classmethod
    def a2md_rawargs(cls, args):
        cls._a2md_args_raw = [] + args

    @classmethod
    def a2md(cls, args, raw=False) -> Dict:
        preargs = cls._a2md_args
        if raw:
            preargs = cls._a2md_args_raw
        print("running: {0} {1}".format(preargs, args))
        return cls.run(preargs + args)

    @classmethod
    def curl(cls, args):
        return cls.run([cls.CURL] + args)

    # --------- HTTP ---------

    @classmethod
    def is_live(cls, url, timeout):
        server = urlparse(url)
        try_until = time.time() + timeout
        print("checking reachability of %s" % url)
        while time.time() < try_until:
            # noinspection PyBroadException
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout)
                c.request('HEAD', server.path)
                _resp = c.getresponse()
                c.close()
                return True
            except ConnectionRefusedError:
                print("connection refused")
                time.sleep(.1)
            except:
                print("Unexpected error:", sys.exc_info()[0])
                time.sleep(.1)
        print("Unable to contact server after %d sec" % timeout)
        return False

    @classmethod
    def is_dead(cls, url, timeout):
        server = urlparse(url)
        try_until = time.time() + timeout
        print("checking reachability of %s" % url)
        while time.time() < try_until:
            # noinspection PyBroadException
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout)
                c.request('HEAD', server.path)
                _resp = c.getresponse()
                c.close()
                time.sleep(.1)
            except IOError:
                return True
            except:
                return True
        print("Server still responding after %d sec" % timeout)
        return False

    @classmethod
    def get_json(cls, url, timeout):
        data = cls.get_plain(url, timeout)
        if data:
            return json.loads(data)
        return None

    @classmethod
    def get_plain(cls, url, timeout):
        server = urlparse(url)
        try_until = time.time() + timeout
        while time.time() < try_until:
            # noinspection PyBroadException
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout)
                c.request('GET', server.path)
                resp = c.getresponse()
                data = resp.read()
                c.close()
                return data
            except IOError:
                print("connect error:", sys.exc_info()[0])
                time.sleep(.1)
            except:
                print("Unexpected error:", sys.exc_info()[0])
        print("Unable to contact server after %d sec" % timeout)
        return None

    @classmethod
    def check_acme(cls):
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

    @classmethod
    def get_httpd_version(cls):
        p = subprocess.run([cls.APXS, "-q", "HTTPD_VERSION"], capture_output=True, text=True)
        if p.returncode != 0:
            return "unknown"
        return p.stdout.strip()

    @classmethod
    def _versiontuple(cls, v):
        return tuple(map(int, v.split('.')))

    @classmethod
    def httpd_is_at_least(cls, minv):
        hv = cls._versiontuple(cls.get_httpd_version())
        return hv >= cls._versiontuple(minv)

    # --------- access local store ---------

    @classmethod
    def purge_store(cls):
        print("purge store dir: %s" % TestEnv.STORE_DIR)
        assert len(TestEnv.STORE_DIR) > 1
        if os.path.exists(TestEnv.STORE_DIR):
            shutil.rmtree(TestEnv.STORE_DIR, ignore_errors=False)
        os.makedirs(TestEnv.STORE_DIR)

    @classmethod
    def clear_store(cls):
        print("clear store dir: %s" % TestEnv.STORE_DIR)
        assert len(TestEnv.STORE_DIR) > 1
        if not os.path.exists(TestEnv.STORE_DIR):
            os.makedirs(TestEnv.STORE_DIR)
        for dirpath in ["challenges", "tmp", "archive", "domains", "accounts", "staging", "ocsp"]:
            shutil.rmtree(os.path.join(TestEnv.STORE_DIR, dirpath), ignore_errors=True)

    @classmethod
    def clear_ocsp_store(cls):
        assert len(TestEnv.STORE_DIR) > 1
        dirpath = os.path.join(TestEnv.STORE_DIR, "ocsp")
        print("clear ocsp store dir: %s" % dir)
        if os.path.exists(dirpath):
            shutil.rmtree(dirpath, ignore_errors=True)

    @classmethod
    def authz_save(cls, name, content):
        dirpath = os.path.join(TestEnv.STORE_DIR, 'staging', name)
        os.makedirs(dirpath)
        open(os.path.join(dirpath, 'authz.json'), "w").write(content)

    @classmethod
    def path_store_json(cls):
        return os.path.join(TestEnv.STORE_DIR, 'md_store.json')

    @classmethod
    def path_account(cls, acct):
        return os.path.join(TestEnv.STORE_DIR, 'accounts', acct, 'account.json')

    @classmethod
    def path_account_key(cls, acct):
        return os.path.join(TestEnv.STORE_DIR, 'accounts', acct, 'account.pem')

    @classmethod
    def store_domains(cls):
        return os.path.join(TestEnv.STORE_DIR, 'domains')

    @classmethod
    def store_archives(cls):
        return os.path.join(TestEnv.STORE_DIR, 'archive')

    @classmethod
    def store_stagings(cls):
        return os.path.join(TestEnv.STORE_DIR, 'staging')

    @classmethod
    def store_challenges(cls):
        return os.path.join(TestEnv.STORE_DIR, 'challenges')

    @classmethod
    def store_domain_file(cls, domain, filename):
        return os.path.join(TestEnv.store_domains(), domain, filename)

    @classmethod
    def store_archived_file(cls, domain, version, filename):
        return os.path.join(TestEnv.store_archives(), "%s.%d" % (domain, version), filename)

    @classmethod
    def store_staged_file(cls, domain, filename):
        return os.path.join(TestEnv.store_stagings(), domain, filename)

    @classmethod
    def path_fallback_cert(cls, domain):
        return os.path.join(TestEnv.STORE_DIR, 'domains', domain, 'fallback-pubcert.pem')

    @classmethod
    def path_job(cls, domain):
        return os.path.join(TestEnv.STORE_DIR, 'staging', domain, 'job.json')

    @classmethod
    def replace_store(cls, src):
        shutil.rmtree(TestEnv.STORE_DIR, ignore_errors=False)
        shutil.copytree(src, TestEnv.STORE_DIR)

    @classmethod
    def list_accounts(cls):
        return os.listdir(os.path.join(TestEnv.STORE_DIR, 'accounts'))

    @classmethod
    def check_md(cls, domain, md=None, state=-1, ca=None, protocol=None, agreement=None, contacts=None):
        domains = None
        if isinstance(domain, list):
            domains = domain
            domain = domains[0]
        if md:
            domain = md
        path = cls.store_domain_file(domain, 'md.json')
        with open(path) as f:
            md = json.load(f)
        assert md
        if domains:
            assert md['domains'] == domains
        if state >= 0:
            assert md['state'] == state
        if ca:
            assert md['ca']['url'] == ca
        if protocol:
            assert md['ca']['proto'] == protocol
        if agreement:
            assert md['ca']['agreement'] == agreement
        if contacts:
            assert md['contacts'] == contacts

    @classmethod
    def pkey_fname(cls, pkeyspec=None):
        if pkeyspec and not re.match(r'^rsa( .+)?$', pkeyspec.lower()):
            return "privkey.{0}.pem".format(pkeyspec)
        return 'privkey.pem'

    @classmethod
    def cert_fname(cls, pkeyspec=None):
        if pkeyspec and not re.match(r'^rsa( .+)?$', pkeyspec.lower()):
            return "pubcert.{0}.pem".format(pkeyspec)
        return 'pubcert.pem'

    @classmethod
    def check_md_complete(cls, domain, pkey=None):
        md = cls.get_md_status(domain)
        assert md
        assert 'state' in md, "md is unexpeted: {0}".format(md)
        assert md['state'] is TestEnv.MD_S_COMPLETE, "unexpected state: {0}".format(md['state'])
        assert os.path.isfile(TestEnv.store_domain_file(domain, cls.pkey_fname(pkey)))
        assert os.path.isfile(TestEnv.store_domain_file(domain, cls.cert_fname(pkey)))

    @classmethod
    def check_md_credentials(cls, domain):
        if isinstance(domain, list):
            domains = domain
            domain = domains[0]
        else:
            domains = [domain]
        # check private key, validate certificate, etc
        CertUtil.validate_privkey(cls.store_domain_file(domain, 'privkey.pem'))
        cert = CertUtil(cls.store_domain_file(domain, 'pubcert.pem'))
        cert.validate_cert_matches_priv_key(cls.store_domain_file(domain, 'privkey.pem'))
        # check SANs and CN
        assert cert.get_cn() == domain
        # compare lists twice in opposite directions: SAN may not respect ordering
        san_list = list(cert.get_san_list())
        assert len(san_list) == len(domains)
        assert set(san_list).issubset(domains)
        assert set(domains).issubset(san_list)
        # check valid dates interval
        not_before = cert.get_not_before()
        not_after = cert.get_not_after()
        assert not_before < datetime.now(not_before.tzinfo)
        assert not_after > datetime.now(not_after.tzinfo)

    # --------- control apache ---------

    @classmethod
    def apachectl(cls, cmd, conf=None, check_live=True):
        if conf:
            assert 1 == 0
        args = [cls.APACHECTL, "-d", cls.WEBROOT, "-k", cmd]
        p = subprocess.run(args, capture_output=True, text=True)
        cls.apachectl_stderr = p.stderr
        rv = p.returncode
        if rv == 0:
            if check_live:
                rv = 0 if cls.is_live(cls.HTTPD_CHECK_URL, 10) else -1
            else:
                rv = 0 if cls.is_dead(cls.HTTPD_CHECK_URL, 10) else -1
                print("waited for a apache.is_dead, rv=%d" % rv)
        else:
            print("exit %d, stderr: %s" % (rv, p.stderr))
        return rv

    @classmethod
    def apache_restart(cls):
        return cls.apachectl("graceful")

    @classmethod
    def apache_start(cls):
        return cls.apachectl("start")

    @classmethod
    def apache_stop(cls):
        return cls.apachectl("stop", check_live=False)

    @classmethod
    def apache_fail(cls):
        rv = cls.apachectl("graceful", check_live=False)
        if rv != 0:
            print("check, if dead: " + cls.HTTPD_CHECK_URL)
            return 0 if cls.is_dead(cls.HTTPD_CHECK_URL, 5) else -1
        return rv

    @classmethod
    def httpd_error_log_clear(cls):
        cls.apachectl_stderr = ""
        if os.path.isfile(cls.ERROR_LOG):
            os.remove(cls.ERROR_LOG)

    RE_MD_RESET = re.compile(r'.*\[md:info].*initializing\.\.\.')
    RE_MD_ERROR = re.compile(r'.*\[md:error].*')
    RE_MD_WARN = re.compile(r'.*\[md:warn].*')

    @classmethod
    def httpd_error_log_count(cls):
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
                m = cls.RE_MD_RESET.match(line)
                if m:
                    ecount = 0
                    wcount = 0
        return ecount, wcount

    @classmethod
    def httpd_error_log_scan(cls, regex):
        if not os.path.isfile(cls.ERROR_LOG):
            return False
        fin = open(cls.ERROR_LOG)
        for line in fin:
            if regex.match(line):
                return True
        return False

    # --------- check utilities ---------

    @classmethod
    def check_json_contains(cls, actual, expected):
        # write all expected key:value bindings to a copy of the actual data ... 
        # ... assert it stays unchanged 
        test_json = copy.deepcopy(actual)
        test_json.update(expected)
        assert actual == test_json

    @classmethod
    def check_file_access(cls, path, exp_mask):
        actual_mask = os.lstat(path).st_mode & 0o777
        assert oct(actual_mask) == oct(exp_mask)

    @classmethod
    def check_dir_empty(cls, path):
        assert os.listdir(path) == []

    @classmethod
    def getStatus(cls, domain, path, use_https=True):
        result = cls.get_meta(domain, path, use_https)
        return result['http_status']

    @classmethod
    def get_cert(cls, domain, tls=None, ciphers=None):
        return CertUtil.load_server_cert(TestEnv.HTTPD_HOST,
                                         TestEnv.HTTPS_PORT, domain, tls=tls, ciphers=ciphers)

    @classmethod
    def get_server_cert(cls, domain, proto=None, ciphers=None):
        args = [
            cls.OPENSSL, "s_client", "-status",
            "-connect", "%s:%s" % (TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT),
            "-CAfile", cls.TEST_CA_PEM,
            "-servername", domain,
            "-showcerts"
        ]
        if proto is not None:
            args.extend(["-{0}".format(proto)])
        if ciphers is not None:
            args.extend(["-cipher", ciphers])
        r = TestEnv.run(args)
        # noinspection PyBroadException
        try:
            return CertUtil.parse_pem_cert(r['stdout'])
        except:
            return None

    @classmethod
    def verify_cert_key_lenghts(cls, domain, pkeys):
        for p in pkeys:
            cert = TestEnv.get_server_cert(domain, proto="tls1_2", ciphers=p['ciphers'])
            if 0 == p['keylen']:
                assert cert is None
            else:
                assert cert, "no cert returned for cipher: {0}".format(p['ciphers'])
                assert cert.get_key_length() == p['keylen'], "what?: {0}".format(cert)

    @classmethod
    def get_meta(cls, domain, path, use_https=True):
        schema = "https" if use_https else "http"
        port = cls.HTTPS_PORT if use_https else cls.HTTP_PORT
        result = TestEnv.curl(["-D", "-", "-k", "--resolve", ("%s:%s:127.0.0.1" % (domain, port)),
                               ("%s://%s:%s%s" % (schema, domain, port, path))])
        assert result['rv'] == 0
        # read status
        m = re.match("HTTP/\\d(\\.\\d)? +(\\d\\d\\d) .*", result['stdout'])
        assert m
        result['http_status'] = int(m.group(2))
        # collect response headers
        h = {}
        for m in re.findall(r'^(\S+): (.*)\n', result['stdout'], re.M):
            h[m[0]] = m[1]
        result['http_headers'] = h
        return result

    @classmethod
    def get_content(cls, domain, path, use_https=True):
        schema = "https" if use_https else "http"
        port = cls.HTTPS_PORT if use_https else cls.HTTP_PORT
        result = TestEnv.curl(["-sk", "--resolve", ("%s:%s:127.0.0.1" % (domain, port)),
                               ("%s://%s:%s%s" % (schema, domain, port, path))])
        assert result['rv'] == 0
        return result['stdout']

    @classmethod
    def get_json_content(cls, domain, path, use_https=True):
        schema = "https" if use_https else "http"
        port = cls.HTTPS_PORT if use_https else cls.HTTP_PORT
        result = TestEnv.curl(["-k", "--resolve", ("%s:%s:127.0.0.1" % (domain, port)),
                               ("%s://%s:%s%s" % (schema, domain, port, path))])
        assert result['rv'] == 0
        return result['jout'] if 'jout' in result else None

    @classmethod
    def get_certificate_status(cls, domain) -> Dict:
        return TestEnv.get_json_content(domain, "/.httpd/certificate-status")

    @classmethod
    def get_md_status(cls, domain) -> Dict:
        return TestEnv.get_json_content("localhost", "/md-status/%s" % domain)

    @classmethod
    def get_server_status(cls, query="/"):
        return TestEnv.get_content("localhost", "/server-status%s" % query)

    @classmethod
    def await_completion(cls, names, must_renew=False, restart=True, timeout=60):
        try_until = time.time() + timeout
        renewals = {}
        while len(names) > 0:
            if time.time() >= try_until:
                return False
            for name in names:
                mds = TestEnv.get_md_status(name)
                if mds is None:
                    print("not managed by md: %s" % name)
                    return False

                if 'renewal' in mds:
                    renewal = mds['renewal']
                    renewals[name] = True
                    if 'finished' in renewal and renewal['finished'] is True:
                        if (not must_renew) or (name in renewals):
                            names.remove(name)

            if len(names) != 0:
                time.sleep(0.1)
        if restart:
            time.sleep(0.1)
            return cls.apache_restart() == 0
        return True

    @classmethod
    def is_renewing(cls, name):
        stat = TestEnv.get_certificate_status(name)
        return 'renewal' in stat

    @classmethod
    def await_renewal(cls, names, timeout=60):
        try_until = time.time() + timeout
        while len(names) > 0:
            if time.time() >= try_until:
                return False
            for name in names:
                md = TestEnv.get_md_status(name)
                if md is None:
                    print("not managed by md: %s" % name)
                    return False

                if 'renewal' in md:
                    names.remove(name)

            if len(names) != 0:
                time.sleep(0.1)
        return True

    @classmethod
    def await_error(cls, domain, timeout=60):
        try_until = time.time() + timeout
        while True:
            if time.time() >= try_until:
                return False
            md = cls.get_md_status(domain)
            if md:
                if 'state' in md and md['state'] == TestEnv.MD_S_ERROR:
                    return md
                if 'renewal' in md and 'errors' in md['renewal'] and md['renewal']['errors'] > 0:
                    return md
            time.sleep(0.1)

    @classmethod
    def await_file(cls, fpath, timeout=60):
        try_until = time.time() + timeout
        while True:
            if time.time() >= try_until:
                return False
            if os.path.isfile(fpath):
                return True
            time.sleep(0.1)

    @classmethod
    def check_file_permissions(cls, domain):
        md = cls.a2md(["list", domain])['jout']['output'][0]
        assert md
        acct = md['ca']['account']
        assert acct
        cls.check_file_access(cls.path_store_json(), 0o600)
        # domains
        cls.check_file_access(cls.store_domains(), 0o700)
        cls.check_file_access(os.path.join(cls.store_domains(), domain), 0o700)
        cls.check_file_access(cls.store_domain_file(domain, 'privkey.pem'), 0o600)
        cls.check_file_access(cls.store_domain_file(domain, 'pubcert.pem'), 0o600)
        cls.check_file_access(cls.store_domain_file(domain, 'md.json'), 0o600)
        # archive
        cls.check_file_access(cls.store_archived_file(domain, 1, 'md.json'), 0o600)
        # accounts
        cls.check_file_access(os.path.join(cls.STORE_DIR, 'accounts'), 0o755)
        cls.check_file_access(os.path.join(cls.STORE_DIR, 'accounts', acct), 0o755)
        cls.check_file_access(cls.path_account(acct), 0o644)
        cls.check_file_access(cls.path_account_key(acct), 0o644)
        # staging
        cls.check_file_access(cls.store_stagings(), 0o755)

    @classmethod
    def get_ocsp_status(cls, domain, proto=None, cipher=None):
        stat = {}
        args = [
            cls.OPENSSL, "s_client", "-status",
            "-connect", "%s:%s" % (TestEnv.HTTPD_HOST, TestEnv.HTTPS_PORT),
            "-CAfile", cls.TEST_CA_PEM,
            "-servername", domain,
            "-showcerts"
        ]
        if proto is not None:
            args.extend(["-{0}".format(proto)])
        if cipher is not None:
            args.extend(["-cipher", cipher])
        r = TestEnv.run(args)
        ocsp_regex = re.compile(r'OCSP response: +([^=\n]+)\n')
        matches = ocsp_regex.finditer(r["stdout"])
        for m in matches:
            if m.group(1) != "":
                stat['ocsp'] = m.group(1)
        if 'ocsp' not in stat:
            ocsp_regex = re.compile(r'OCSP Response Status:\s*(.+)')
            matches = ocsp_regex.finditer(r["stdout"])
            for m in matches:
                if m.group(1) != "":
                    stat['ocsp'] = m.group(1)
        verify_regex = re.compile(r'Verify return code:\s*(.+)')
        matches = verify_regex.finditer(r["stdout"])
        for m in matches:
            if m.group(1) != "":
                stat['verify'] = m.group(1)
        return stat

    @classmethod
    def await_ocsp_status(cls, domain, timeout=60):
        try_until = time.time() + timeout
        while True:
            if time.time() >= try_until:
                return False
            stat = cls.get_ocsp_status(domain)
            if 'ocsp' in stat and stat['ocsp'] != "no response sent":
                return stat
            time.sleep(0.1)

    @classmethod
    def create_self_signed_cert(cls, name_list, valid_days, serial=1000, path=None):
        dirpath = path
        if not path:
            dirpath = os.path.join(cls.store_domains(), name_list[0])
        return CertUtil.create_self_signed_cert(dirpath, name_list, valid_days, serial)
