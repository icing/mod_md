import copy
import inspect
import json
import logging

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

from md_cert_util import MDCertUtil


log = logging.getLogger(__name__)


class Dummy:
    pass


class MDTestEnv:

    MD_S_UNKNOWN = 0
    MD_S_INCOMPLETE = 1
    MD_S_COMPLETE = 2
    MD_S_EXPIRED = 3
    MD_S_ERROR = 4

    EMPTY_JOUT = {'status': 0, 'output': []}

    DOMAIN_SUFFIX = "%d.org" % time.time()
    LOG_FMT_TIGHT = '%(levelname)s: %(message)s'

    apachectl_stderr = None

    _SSL_MODULE = None

    @classmethod
    def get_ssl_module(cls):
        if cls._SSL_MODULE is None:
            cls._SSL_MODULE = os.environ['SSL_MODULE'] if 'SSL_MODULE' in os.environ else "ssl"
        return cls._SSL_MODULE

    def __init__(self, pytestconfig=None):
        logging.getLogger('').setLevel(level=logging.DEBUG)

        our_dir = os.path.dirname(inspect.getfile(MDTestEnv))
        config = ConfigParser()
        config.read(os.path.join(our_dir, 'test.ini'))
        self.TEST_SRC = our_dir
        self.PREFIX = config.get('global', 'prefix')

        self.GEN_DIR = config.get('global', 'gen_dir')

        self.WEBROOT = config.get('global', 'server_dir')
        self.HOSTNAME = config.get('global', 'server_name')
        self.TESTROOT = os.path.join(self.WEBROOT, '..', '..')

        self.APACHECTL = os.path.join(self.PREFIX, 'bin', 'apachectl')
        self.APXS = os.path.join(self.PREFIX, 'bin', 'apxs')
        self.ERROR_LOG = os.path.join(self.WEBROOT, "logs", "error_log")
        self.APACHE_CONF_DIR = os.path.join(self.WEBROOT, "conf")
        self.APACHE_TEST_CONF = os.path.join(self.APACHE_CONF_DIR, "test.conf")
        self.APACHE_SSL_DIR = os.path.join(self.APACHE_CONF_DIR, "ssl")
        self.APACHE_CONF = os.path.join(self.APACHE_CONF_DIR, "httpd.conf")
        self.APACHE_CONF_SRC = "data"
        self.APACHE_HTDOCS_DIR = os.path.join(self.WEBROOT, "htdocs")

        self.HTTP_PORT = config.get('global', 'http_port')
        self.HTTPS_PORT = config.get('global', 'https_port')
        self.HTTP_PROXY_PORT = config.get('global', 'http_proxy_port')
        self.HTTPD_HOST = "localhost"
        self.HTTPD_URL = "http://" + self.HTTPD_HOST + ":" + self.HTTP_PORT
        self.HTTPD_URL_SSL = "https://" + self.HTTPD_HOST + ":" + self.HTTPS_PORT
        self.HTTPD_PROXY_URL = "http://" + self.HTTPD_HOST + ":" + self.HTTP_PROXY_PORT
        self.HTTPD_CHECK_URL = self.HTTPD_URL

        self.ACME_URL_DEFAULT = config.get('acme', 'url_default')
        self.ACME_URL = config.get('acme', 'url')
        self.ACME_TOS = config.get('acme', 'tos')
        self.ACME_SERVER = config.get('acme', 'server').strip()
        self.ACME_LACKS_OCSP = (self.ACME_SERVER == 'pebble')
        self.ACME_SERVER_DOWN = False
        self.ACME_SERVER_OK = False

        self.TEST_CA_PEM = os.path.join(our_dir, "gen/apache/test-ca.pem")

        self.A2MD = os.path.join(our_dir, config.get('global', 'a2md_bin'))
        self.A2MD_VERSION = config.get('global', 'a2md_version')

        self.CURL = config.get('global', 'curl_bin')
        self.OPENSSL = config.get('global', 'openssl_bin')

        self.STORE_DIR = "./md"
        self.set_store_dir_default()
        self.clear_store()

        self._httpd_base_conf = f"""
        H2MinWorkers 1
        H2MaxWorkers 64
        SSLSessionCache "shmcb:ssl_gcache_data(32000)"
        """
        self._verbosity = pytestconfig.option.verbose if pytestconfig is not None else 0
        if self._verbosity >= 2:
            self._httpd_base_conf += f"""
                LogLevel http2:trace2 h2test:trace2 proxy_http2:trace2 
                LogLevel core:trace5 
                """
        elif self._verbosity >= 2:
            self._httpd_base_conf += "LogLevel http2:debug h2test:trace2 proxy_http2:trace2"
        else:
            self._httpd_base_conf += "LogLevel http2:info h2test:trace2 proxy_http2:info"

    @classmethod
    def is_pebble(self) -> bool:
        our_dir = os.path.dirname(inspect.getfile(MDTestEnv))
        config = ConfigParser()
        config.read(os.path.join(our_dir, 'test.ini'))
        ACME_SERVER = config.get('acme', 'server').strip()
        return ACME_SERVER == 'pebble'

    @classmethod
    def lacks_ocsp(cls):
        return cls.is_pebble()

    def set_store_dir_default(self):
        dirpath = "md"
        if self.httpd_is_at_least("2.5.0"):
            dirpath = os.path.join("state", dirpath)
        self.set_store_dir(dirpath)

    def set_store_dir(self, dirpath):
        self.STORE_DIR = os.path.join(self.WEBROOT, dirpath)
        if self.ACME_URL:
            self.a2md_stdargs([self.A2MD, "-a", self.ACME_URL, "-d", self.STORE_DIR,  "-C", self.TEST_CA_PEM, "-j"])
            self.a2md_rawargs([self.A2MD, "-a", self.ACME_URL, "-d", self.STORE_DIR,  "-C", self.TEST_CA_PEM])

    def get_request_domain(self, request):
        return "%s-%s" % (re.sub(r'[_]', '-', request.node.originalname), MDTestEnv.DOMAIN_SUFFIX)

    def get_method_domain(self, method):
        return "%s-%s" % (re.sub(r'[_]', '-', method.__name__.lower()), MDTestEnv.DOMAIN_SUFFIX)

    def get_module_domain(self, module):
        return "%s-%s" % (re.sub(r'[_]', '-', module.__name__.lower()), MDTestEnv.DOMAIN_SUFFIX)

    def get_class_domain(self, c):
        return "%s-%s" % (re.sub(r'[_]', '-', c.__name__.lower()), MDTestEnv.DOMAIN_SUFFIX)

    # --------- cmd execution ---------

    _a2md_args = []
    _a2md_args_raw = []

    def run(self, args, _input=None):
        # log.debug("run: {0}".format(" ".join(args)))
        p = subprocess.run(args, capture_output=True, text=True)
        # noinspection PyBroadException
        try:
            jout = json.loads(p.stdout)
        except:
            jout = None
        return {
            "rv": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "jout": jout
        }

    def a2md_stdargs(self, args):
        self._a2md_args = [] + args

    def a2md_rawargs(self, args):
        self._a2md_args_raw = [] + args

    def a2md(self, args, raw=False) -> Dict:
        preargs = self._a2md_args
        if raw:
            preargs = self._a2md_args_raw
        log.debug("running: {0} {1}".format(preargs, args))
        return self.run(preargs + args)

    def curl(self, args):
        return self.run([self.CURL] + args)

    # --------- HTTP ---------

    def is_live(self, url, timeout):
        server = urlparse(url)
        try_until = time.time() + timeout
        log.debug("checking reachability of %s", url)
        last_err = ""
        while time.time() < try_until:
            # noinspection PyBroadException
            try:
                r = self.curl(["-sk", "--resolve",
                               "%s:%s:127.0.0.1" % (server.hostname, server.port),
                               "-D", "-", "%s" % url])
                if r['rv'] == 0:
                    return True
                time.sleep(.1)
            except ConnectionRefusedError:
                log.debug("connection refused")
                time.sleep(.1)
            except:
                if last_err != str(sys.exc_info()[0]):
                    last_err = str(sys.exc_info()[0])
                    log.debug("Unexpected error: %s", last_err)
                time.sleep(.1)
        log.debug("Unable to contact server after %d sec", timeout)
        return False

    def is_dead(self, url, timeout):
        server = urlparse(url)
        try_until = time.time() + timeout
        log.debug("checking reachability of %s" % url)
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
        log.debug("Server still responding after %d sec" % timeout)
        return False

    def get_json(self, url, timeout):
        data = self.get_plain(url, timeout)
        if data:
            return json.loads(data)
        return None

    def get_plain(self, url, timeout):
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
                log.error("connect error:", sys.exc_info()[0])
                time.sleep(.1)
            except:
                log.error("Unexpected error:", sys.exc_info()[0])
        log.error("Unable to contact server after %d sec" % timeout)
        return None

    def check_acme(self):
        if self.ACME_SERVER_OK:
            return True
        if self.ACME_SERVER_DOWN:
            pytest.skip(msg="ACME server not running")
            return False
        if self.is_live(self.ACME_URL, 0.5):
            self.ACME_SERVER_OK = True
            return True
        else:
            self.ACME_SERVER_DOWN = True
            pytest.fail(msg="ACME server not running", pytrace=False)
            return False

    def get_httpd_version(self):
        p = subprocess.run([self.APXS, "-q", "HTTPD_VERSION"], capture_output=True, text=True)
        if p.returncode != 0:
            return "unknown"
        return p.stdout.strip()

    def _versiontuple(self, v):
        return tuple(map(int, v.split('.')))

    def httpd_is_at_least(self, minv):
        hv = self._versiontuple(self.get_httpd_version())
        return hv >= self._versiontuple(minv)

    # --------- access local store ---------

    def purge_store(self):
        log.debug("purge store dir: %s" % self.STORE_DIR)
        assert len(self.STORE_DIR) > 1
        if os.path.exists(self.STORE_DIR):
            shutil.rmtree(self.STORE_DIR, ignore_errors=False)
        os.makedirs(self.STORE_DIR)

    def clear_store(self):
        log.debug("clear store dir: %s" % self.STORE_DIR)
        assert len(self.STORE_DIR) > 1
        if not os.path.exists(self.STORE_DIR):
            os.makedirs(self.STORE_DIR)
        for dirpath in ["challenges", "tmp", "archive", "domains", "accounts", "staging", "ocsp"]:
            shutil.rmtree(os.path.join(self.STORE_DIR, dirpath), ignore_errors=True)

    def clear_ocsp_store(self):
        assert len(self.STORE_DIR) > 1
        dirpath = os.path.join(self.STORE_DIR, "ocsp")
        log.debug("clear ocsp store dir: %s" % dir)
        if os.path.exists(dirpath):
            shutil.rmtree(dirpath, ignore_errors=True)

    def authz_save(self, name, content):
        dirpath = os.path.join(self.STORE_DIR, 'staging', name)
        os.makedirs(dirpath)
        open(os.path.join(dirpath, 'authz.json'), "w").write(content)

    def path_store_json(self):
        return os.path.join(self.STORE_DIR, 'md_store.json')

    def path_account(self, acct):
        return os.path.join(self.STORE_DIR, 'accounts', acct, 'account.json')

    def path_account_key(self, acct):
        return os.path.join(self.STORE_DIR, 'accounts', acct, 'account.pem')

    def store_domains(self):
        return os.path.join(self.STORE_DIR, 'domains')

    def store_archives(self):
        return os.path.join(self.STORE_DIR, 'archive')

    def store_stagings(self):
        return os.path.join(self.STORE_DIR, 'staging')

    def store_challenges(self):
        return os.path.join(self.STORE_DIR, 'challenges')

    def store_domain_file(self, domain, filename):
        return os.path.join(self.store_domains(), domain, filename)

    def store_archived_file(self, domain, version, filename):
        return os.path.join(self.store_archives(), "%s.%d" % (domain, version), filename)

    def store_staged_file(self, domain, filename):
        return os.path.join(self.store_stagings(), domain, filename)

    def path_fallback_cert(self, domain):
        return os.path.join(self.STORE_DIR, 'domains', domain, 'fallback-pubcert.pem')

    def path_job(self, domain):
        return os.path.join(self.STORE_DIR, 'staging', domain, 'job.json')

    def replace_store(self, src):
        shutil.rmtree(self.STORE_DIR, ignore_errors=False)
        shutil.copytree(src, self.STORE_DIR)

    def list_accounts(self):
        return os.listdir(os.path.join(self.STORE_DIR, 'accounts'))

    def check_md(self, domain, md=None, state=-1, ca=None, protocol=None, agreement=None, contacts=None):
        domains = None
        if isinstance(domain, list):
            domains = domain
            domain = domains[0]
        if md:
            domain = md
        path = self.store_domain_file(domain, 'md.json')
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

    def pkey_fname(self, pkeyspec=None):
        if pkeyspec and not re.match(r'^rsa( ?\d+)?$', pkeyspec.lower()):
            return "privkey.{0}.pem".format(pkeyspec)
        return 'privkey.pem'

    def cert_fname(self, pkeyspec=None):
        if pkeyspec and not re.match(r'^rsa( ?\d+)?$', pkeyspec.lower()):
            return "pubcert.{0}.pem".format(pkeyspec)
        return 'pubcert.pem'

    def check_md_complete(self, domain, pkey=None):
        md = self.get_md_status(domain)
        assert md
        assert 'state' in md, "md is unexpected: {0}".format(md)
        assert md['state'] is MDTestEnv.MD_S_COMPLETE, "unexpected state: {0}".format(md['state'])
        assert os.path.isfile(self.store_domain_file(domain, self.pkey_fname(pkey)))
        assert os.path.isfile(self.store_domain_file(domain, self.cert_fname(pkey)))

    def check_md_credentials(self, domain):
        if isinstance(domain, list):
            domains = domain
            domain = domains[0]
        else:
            domains = [domain]
        # check private key, validate certificate, etc
        MDCertUtil.validate_privkey(self.store_domain_file(domain, 'privkey.pem'))
        cert = MDCertUtil(self.store_domain_file(domain, 'pubcert.pem'))
        cert.validate_cert_matches_priv_key(self.store_domain_file(domain, 'privkey.pem'))
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

    def apachectl(self, cmd, conf=None, check_live=True, check_url: str = None):
        if conf:
            assert 1 == 0
        args = [self.APACHECTL, "-d", self.WEBROOT, "-k", cmd]
        p = subprocess.run(args, capture_output=True, text=True)
        self.apachectl_stderr = p.stderr
        rv = p.returncode
        if rv == 0:
            if check_url is None:
                check_url = self.HTTPD_CHECK_URL
            if check_live:
                rv = 0 if self.is_live(check_url, 10) else -1
            else:
                rv = 0 if self.is_dead(check_url, 10) else -1
                log.debug("waited for a apache.is_dead, rv=%d" % rv)
        else:
            log.debug("exit %d, stderr: %s" % (rv, p.stderr))
        return rv

    def apache_restart(self, check_url: str = None):
        return self.apachectl("graceful", check_url=check_url)

    def apache_start(self):
        return self.apachectl("start")

    def apache_stop(self):
        return self.apachectl("stop", check_live=False)

    def apache_fail(self):
        rv = self.apachectl("graceful", check_live=False)
        if rv != 0:
            log.debug("check, if dead: " + self.HTTPD_CHECK_URL)
            return 0 if self.is_dead(self.HTTPD_CHECK_URL, 5) else -1
        return rv

    def apache_error_log_clear(self):
        self.apachectl_stderr = ""
        if os.path.isfile(self.ERROR_LOG):
            os.remove(self.ERROR_LOG)

    RE_MD_RESET = re.compile(r'.*\[md:info].*initializing\.\.\.')
    RE_MD_ERROR = re.compile(r'.*\[md:error].*')
    RE_MD_WARN = re.compile(r'.*\[md:warn].*')

    def httpd_error_log_count(self):
        ecount = 0
        wcount = 0

        if os.path.isfile(self.ERROR_LOG):
            fin = open(self.ERROR_LOG)
            for line in fin:
                m = self.RE_MD_ERROR.match(line)
                if m:
                    ecount += 1
                    continue
                m = self.RE_MD_WARN.match(line)
                if m:
                    wcount += 1
                    continue
                m = self.RE_MD_RESET.match(line)
                if m:
                    ecount = 0
                    wcount = 0
        return ecount, wcount

    def httpd_error_log_scan(self, regex):
        if not os.path.isfile(self.ERROR_LOG):
            return False
        fin = open(self.ERROR_LOG)
        for line in fin:
            if regex.match(line):
                return True
        return False

    RE_APLOGNO = re.compile(r'.*\[(?P<module>[^:]+):(error|warn)].* (?P<aplogno>AH\d+): .+')
    RE_ERRLOG_ERROR = re.compile(r'.*\[(?P<module>[^:]+):error].*')
    RE_ERRLOG_WARN = re.compile(r'.*\[(?P<module>[^:]+):warn].*')
    RE_NOTIFY_ERR = re.compile(r'.*\[urn:org:apache:httpd:log:AH10108:.+')

    def apache_errors_and_warnings(self):
        errors = []
        warnings = []

        if os.path.isfile(self.ERROR_LOG):
            for line in open(self.ERROR_LOG):
                m = self.RE_APLOGNO.match(line)
                if m and m.group('aplogno') in [
                    'AH01873',  # ssl session cache not configured
                    'AH10085',  # warning about fallback cert active
                    'AH02217',  # ssl_stapling init error
                    'AH02604',  # ssl unable to configure our self signed for stapling
                    'AH10045',  # md reports a non match domain to vhosts
                ]:
                    # we know these happen normally in our tests
                    continue
                m = self.RE_NOTIFY_ERR.match(line)
                if m:
                    continue
                m = self.RE_ERRLOG_ERROR.match(line)
                if m and m.group('module') not in ['cgid']:
                    errors.append(line)
                    continue
                m = self.RE_ERRLOG_WARN.match(line)
                if m:
                    warnings.append(line)
                    continue
        return errors, warnings

    # --------- check utilities ---------

    def check_json_contains(self, actual, expected):
        # write all expected key:value bindings to a copy of the actual data ... 
        # ... assert it stays unchanged 
        test_json = copy.deepcopy(actual)
        test_json.update(expected)
        assert actual == test_json

    def check_file_access(self, path, exp_mask):
        actual_mask = os.lstat(path).st_mode & 0o777
        assert oct(actual_mask) == oct(exp_mask)

    def check_dir_empty(self, path):
        assert os.listdir(path) == []

    def getStatus(self, domain, path, use_https=True):
        result = self.get_meta(domain, path, use_https)
        return result['http_status']

    def get_cert(self, domain, tls=None, ciphers=None):
        return MDCertUtil.load_server_cert(self.HTTPD_HOST,
                                           self.HTTPS_PORT, domain, tls=tls, ciphers=ciphers)

    def get_server_cert(self, domain, proto=None, ciphers=None):
        args = [
            self.OPENSSL, "s_client", "-status",
            "-connect", "%s:%s" % (self.HTTPD_HOST, self.HTTPS_PORT),
            "-CAfile", self.TEST_CA_PEM,
            "-servername", domain,
            "-showcerts"
        ]
        if proto is not None:
            args.extend(["-{0}".format(proto)])
        if ciphers is not None:
            args.extend(["-cipher", ciphers])
        r = self.run(args)
        # noinspection PyBroadException
        try:
            return MDCertUtil.parse_pem_cert(r['stdout'])
        except:
            return None

    def verify_cert_key_lenghts(self, domain, pkeys):
        for p in pkeys:
            cert = self.get_server_cert(domain, proto="tls1_2", ciphers=p['ciphers'])
            if 0 == p['keylen']:
                assert cert is None
            else:
                assert cert, "no cert returned for cipher: {0}".format(p['ciphers'])
                assert cert.get_key_length() == p['keylen'], "key length, expected {0}, got {1}".format(
                    p['keylen'], cert.get_key_length()
                )

    def get_meta(self, domain, path, use_https=True):
        schema = "https" if use_https else "http"
        port = self.HTTPS_PORT if use_https else self.HTTP_PORT
        result = self.curl(["-D", "-", "-k", "--resolve", ("%s:%s:127.0.0.1" % (domain, port)),
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

    def get_content(self, domain, path, use_https=True):
        schema = "https" if use_https else "http"
        port = self.HTTPS_PORT if use_https else self.HTTP_PORT
        result = self.curl(["-sk", "--resolve", ("%s:%s:127.0.0.1" % (domain, port)),
                            ("%s://%s:%s%s" % (schema, domain, port, path))])
        assert result['rv'] == 0
        return result['stdout']

    def get_json_content(self, domain, path, use_https=True):
        schema = "https" if use_https else "http"
        port = self.HTTPS_PORT if use_https else self.HTTP_PORT
        result = self.curl(["-k", "--resolve", ("%s:%s:127.0.0.1" % (domain, port)),
                            ("%s://%s:%s%s" % (schema, domain, port, path))])
        assert result['rv'] == 0, result['stderr']
        return result['jout'] if 'jout' in result else None

    def get_certificate_status(self, domain) -> Dict:
        return self.get_json_content(domain, "/.httpd/certificate-status")

    def get_md_status(self, domain) -> Dict:
        return self.get_json_content("not-forbidden.org", "/md-status/%s" % domain)

    def get_server_status(self, query="/"):
        return self.get_content("not-forbidden.org", "/server-status%s" % query)

    def await_completion(self, names, must_renew=False, restart=True, timeout=60):
        try_until = time.time() + timeout
        renewals = {}
        while len(names) > 0:
            if time.time() >= try_until:
                return False
            for name in names:
                mds = self.get_md_status(name)
                if mds is None:
                    log.debug("not managed by md: %s" % name)
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
            return self.apache_restart() == 0
        return True

    def is_renewing(self, name):
        stat = self.get_certificate_status(name)
        return 'renewal' in stat

    def await_renewal(self, names, timeout=60):
        try_until = time.time() + timeout
        while len(names) > 0:
            if time.time() >= try_until:
                return False
            for name in names:
                md = self.get_md_status(name)
                if md is None:
                    log.debug("not managed by md: %s" % name)
                    return False

                if 'renewal' in md:
                    names.remove(name)

            if len(names) != 0:
                time.sleep(0.1)
        return True

    def await_error(self, domain, timeout=60):
        try_until = time.time() + timeout
        while True:
            if time.time() >= try_until:
                return False
            md = self.get_md_status(domain)
            if md:
                if 'state' in md and md['state'] == MDTestEnv.MD_S_ERROR:
                    return md
                if 'renewal' in md and 'errors' in md['renewal'] and md['renewal']['errors'] > 0:
                    return md
            time.sleep(0.1)

    def await_file(self, fpath, timeout=60):
        try_until = time.time() + timeout
        while True:
            if time.time() >= try_until:
                return False
            if os.path.isfile(fpath):
                return True
            time.sleep(0.1)

    def check_file_permissions(self, domain):
        md = self.a2md(["list", domain])['jout']['output'][0]
        assert md
        acct = md['ca']['account']
        assert acct
        self.check_file_access(self.path_store_json(), 0o600)
        # domains
        self.check_file_access(self.store_domains(), 0o700)
        self.check_file_access(os.path.join(self.store_domains(), domain), 0o700)
        self.check_file_access(self.store_domain_file(domain, 'privkey.pem'), 0o600)
        self.check_file_access(self.store_domain_file(domain, 'pubcert.pem'), 0o600)
        self.check_file_access(self.store_domain_file(domain, 'md.json'), 0o600)
        # archive
        self.check_file_access(self.store_archived_file(domain, 1, 'md.json'), 0o600)
        # accounts
        self.check_file_access(os.path.join(self.STORE_DIR, 'accounts'), 0o755)
        self.check_file_access(os.path.join(self.STORE_DIR, 'accounts', acct), 0o755)
        self.check_file_access(self.path_account(acct), 0o644)
        self.check_file_access(self.path_account_key(acct), 0o644)
        # staging
        self.check_file_access(self.store_stagings(), 0o755)

    def get_ocsp_status(self, domain, proto=None, cipher=None):
        stat = {}
        args = [
            self.OPENSSL, "s_client", "-status",
            "-connect", "%s:%s" % (self.HTTPD_HOST, self.HTTPS_PORT),
            "-CAfile", self.TEST_CA_PEM,
            "-servername", domain,
            "-showcerts"
        ]
        if proto is not None:
            args.extend(["-{0}".format(proto)])
        if cipher is not None:
            args.extend(["-cipher", cipher])
        r = self.run(args)
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

    def await_ocsp_status(self, domain, timeout=10):
        try_until = time.time() + timeout
        while True:
            if time.time() >= try_until:
                break
            stat = self.get_ocsp_status(domain)
            if 'ocsp' in stat and stat['ocsp'] != "no response sent":
                return stat
            time.sleep(0.1)
        raise TimeoutError(f"ocsp respopnse not available: {domain}")

    def create_self_signed_cert(self, name_list, valid_days, serial=1000, path=None):
        dirpath = path
        if not path:
            dirpath = os.path.join(self.store_domains(), name_list[0])
        return MDCertUtil.create_self_signed_cert(dirpath, name_list, valid_days, serial)
