import copy
import inspect
import json
import logging
from string import Template

import pytest
import re
import os
import shutil
import subprocess
import sys
import time

from datetime import datetime, timedelta
from configparser import ConfigParser, ExtendedInterpolation
from http.client import HTTPConnection
from typing import Dict, List, Optional
from urllib.parse import urlparse

from md_cert_util import MDCertUtil
from md_certs import Credentials

log = logging.getLogger(__name__)


class MDTestSetup:

    # the modules we want to load
    MODULES = [
        "log_config",
        "logio",
        "unixd",
        "version",
        "watchdog",
        "authn_core",
        "authz_host",
        "authz_groupfile",
        "authz_user",
        "authz_core",
        "access_compat",
        "auth_basic",
        "cache",
        "cache_disk",
        "cache_socache",
        "socache_shmcb",
        "dumpio",
        "reqtimeout",
        "filter",
        "mime",
        "env",
        "headers",
        "setenvif",
        "slotmem_shm",
        "status",
        "autoindex",
        "cgid",
        "dir",
        "alias",
        "rewrite",
        "deflate",
        "proxy",
        "proxy_http",
        "proxy_connect",
    ]

    def __init__(self, env: 'MDTestEnv'):
        self.env = env

    def make(self):
        self._make_dirs()
        self._make_conf()
        self._make_htdocs()
        self._make_modules_conf()

    def _make_dirs(self):
        if os.path.exists(self.env.gen_dir):
            shutil.rmtree(self.env.gen_dir)
        os.makedirs(self.env.gen_dir)
        if not os.path.exists(self.env.server_logs_dir):
            os.makedirs(self.env.server_logs_dir)

    def _make_conf(self):
        conf_src_dir = os.path.join(self.env.test_dir, 'conf')
        conf_dest_dir = os.path.join(self.env.server_dir, 'conf')
        if not os.path.exists(conf_dest_dir):
            os.makedirs(conf_dest_dir)
        for name in os.listdir(conf_src_dir):
            src_path = os.path.join(conf_src_dir, name)
            m = re.match(r'(.+).template', name)
            if m:
                self._make_template(src_path, os.path.join(conf_dest_dir, m.group(1)))
            elif os.path.isfile(src_path):
                shutil.copy(src_path, os.path.join(conf_dest_dir, name))

    def _make_template(self, src, dest):
        var_map = dict()
        for name, value in self.env.__class__.__dict__.items():
            if isinstance(value, property):
                var_map[name] = value.fget(self.env)
        t = Template(''.join(open(src).readlines()))
        with open(dest, 'w') as fd:
            fd.write(t.substitute(var_map))

    def _make_htdocs(self):
        if not os.path.exists(self.env.server_docs_dir):
            os.makedirs(self.env.server_docs_dir)
        shutil.copytree(os.path.join(self.env.test_dir, 'htdocs'),
                        os.path.join(self.env.server_dir, 'htdocs'),
                        dirs_exist_ok=True)

    def _make_modules_conf(self):
        modules_conf = os.path.join(self.env.server_dir, 'conf/modules.conf')
        with open(modules_conf, 'w') as fd:
            # issue load directives for all modules we want that are shared
            for m in self.MODULES:
                mod_path = os.path.join(self.env.libexec_dir, f"mod_{m}.so")
                if os.path.isfile(mod_path):
                    fd.write(f"LoadModule {m}_module   \"{mod_path}\"\n")
            for m in ["md"]:
                fd.write(f"LoadModule {m}_module   \"{self.env.libexec_dir}/mod_{m}.so\"\n")


class ExecResult:

    def __init__(self, exit_code: int, stdout: bytes, stderr: bytes = None, duration: timedelta = None):
        self._exit_code = exit_code
        self._raw = stdout if stdout else b''
        self._stdout = stdout.decode() if stdout is not None else ""
        self._stderr = stderr.decode() if stderr is not None else ""
        self._duration = duration if duration is not None else timedelta()
        self._response = None
        self._results = {}
        self._assets = []
        # noinspection PyBroadException
        try:
            self._json_out = json.loads(self._stdout)
        except:
            self._json_out = None

    @property
    def exit_code(self) -> int:
        return self._exit_code

    @property
    def outraw(self) -> bytes:
        return self._raw

    @property
    def stdout(self) -> str:
        return self._stdout

    @property
    def json(self) -> Optional[Dict]:
        """Output as JSON dictionary or None if not parseable."""
        return self._json_out

    @property
    def stderr(self) -> str:
        return self._stderr

    @property
    def duration(self) -> timedelta:
        return self._duration

    @property
    def response(self) -> Optional[Dict]:
        return self._response

    @property
    def results(self) -> Dict:
        return self._results

    @property
    def assets(self) -> List:
        return self._assets

    def add_response(self, resp: Dict):
        if self._response:
            resp['previous'] = self._response
        self._response = resp

    def add_results(self, results: Dict):
        self._results.update(results)
        if 'response' in results:
            self.add_response(results['response'])

    def add_assets(self, assets: List):
        self._assets.extend(assets)


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
    def get_ssl_type(cls):
        if cls._SSL_MODULE is None:
            cls._SSL_MODULE = os.environ['SSL_MODULE'] if 'SSL_MODULE' in os.environ else "ssl"
        return cls._SSL_MODULE

    @classmethod
    def get_acme_server(cls):
        our_dir = os.path.dirname(inspect.getfile(MDTestEnv))
        config = ConfigParser(interpolation=ExtendedInterpolation())
        config.read(os.path.join(our_dir, 'config.ini'))
        return config.get('acme', 'server').strip()

    @classmethod
    def has_acme_server(cls):
        return cls.get_acme_server() != 'none'

    @classmethod
    def has_acme_eab(cls):
        return cls.get_acme_server() == 'pebble'

    @classmethod
    def is_pebble(cls) -> bool:
        return cls.get_acme_server() == 'pebble'

    @classmethod
    def lacks_ocsp(cls):
        return cls.is_pebble()

    def __init__(self, pytestconfig=None):
        logging.getLogger('').setLevel(level=logging.DEBUG)

        our_dir = os.path.dirname(inspect.getfile(MDTestEnv))
        self.config = ConfigParser(interpolation=ExtendedInterpolation())
        self.config.read(os.path.join(our_dir, 'config.ini'))

        self._apxs = self.config.get('global', 'apxs')
        self._prefix = self.config.get('global', 'prefix')
        self._apachectl = self.config.get('global', 'apachectl')
        self._libexec_dir = self.get_apxs_var('LIBEXECDIR')

        self._curl = self.config.get('global', 'curl_bin')
        self._openssl = self.config.get('global', 'openssl_bin')
        self._ca = None

        self._http_port = int(self.config.get('test', 'http_port'))
        self._https_port = int(self.config.get('test', 'https_port'))
        self._proxy_port = int(self.config.get('test', 'proxy_port'))
        self._http_tld = self.config.get('test', 'http_tld')
        self._test_dir = self.config.get('test', 'test_dir')
        self._test_src_dir = self.config.get('test', 'test_src_dir')
        self._gen_dir = self.config.get('test', 'gen_dir')
        self._server_dir = os.path.join(self._gen_dir, 'apache')
        self._server_conf_dir = os.path.join(self._server_dir, "conf")
        self._server_docs_dir = os.path.join(self._server_dir, "htdocs")
        self._server_logs_dir = os.path.join(self.server_dir, "logs")
        self._server_error_log = os.path.join(self._server_logs_dir, "error_log")
        self._apxs = self.config.get('global', 'apxs')

        self._server_user = self.config.get('httpd', 'user')

        self._acme_server = self.config.get('acme', 'server').strip()
        self._acme_url_default = self.config.get('acme', 'url_default')
        self._acme_url = self.config.get('acme', 'url')
        self._acme_tos = self.config.get('acme', 'tos')
        self._acme_server_down = False
        self._acme_server_ok = False

        self._acme_ca_pemfile = os.path.join(our_dir, "gen/apache/acme-ca.pem")
        self._a2md_bin = self.config.get('global', 'a2md_bin')
        self._md_version = self.config.get('md', 'version')

        self._default_domain = f"www.{self._http_tld}"
        self._domains = [
            self._default_domain,
        ]
        self._expired_domains = [
            f"expired.{self._http_tld}",
        ]
        self._mpm_type = os.environ['MPM'] if 'MPM' in os.environ else 'event'
        self._ssl_type = self.get_ssl_type()

        self._httpd_addr = "127.0.0.1"
        self._http_base = f"http://{self._httpd_addr}:{self.http_port}"
        self._https_base = f"https://{self._httpd_addr}:{self.https_port}"
        self._proxy_base = f"http://{self._httpd_addr}:{self.proxy_port}"

        self._store_dir = "./md"
        self.set_store_dir_default()
        self.clear_store()

        self._test_conf = os.path.join(self._server_conf_dir, "test.conf")
        self._httpd_base_conf = [
            f"LoadModule mpm_{self.mpm_type}_module  \"{self.libexec_dir}/mod_mpm_{self.mpm_type}.so\"",
            f"LoadModule {self._ssl_type}_module  \"{self.prefix}/modules/mod_{self._ssl_type}.so\"",
            f"LogLevel {self._ssl_type}:info",
            f"SSLSessionCache \"shmcb:ssl_gcache_data(32000)\"",
            "",
        ]

        self._verbosity = pytestconfig.option.verbose if pytestconfig is not None else 0
        if self._verbosity > 2:
            self._httpd_base_conf.append("LogLevel md:trace4 core:trace5")
        elif self._verbosity == 2:
            self._httpd_base_conf.append("LogLevel md:trace2")
        elif self._verbosity == 1:
            self._httpd_base_conf.append("LogLevel md:debug")
        else:
            self._httpd_base_conf.append("LogLevel md:info")
        self._httpd_base_conf.append("")
        self._setup = MDTestSetup(env=self)
        self._setup.make()

    @property
    def gen_dir(self):
        return self._gen_dir

    @property
    def server_dir(self):
        return self._server_dir

    @property
    def test_dir(self):
        return self._test_dir

    @property
    def server_logs_dir(self):
        return self._server_logs_dir

    @property
    def server_user(self):
        return self._server_user

    def set_store_dir_default(self):
        dirpath = "md"
        if self.httpd_is_at_least("2.5.0"):
            dirpath = os.path.join("state", dirpath)
        self.set_store_dir(dirpath)

    def set_store_dir(self, dirpath):
        self._store_dir = os.path.join(self.server_dir, dirpath)
        if self.acme_url:
            self.a2md_stdargs([self.a2md_bin, "-a", self.acme_url, "-d", self._store_dir,  "-C", self.acme_ca_pemfile, "-j"])
            self.a2md_rawargs([self.a2md_bin, "-a", self.acme_url, "-d", self._store_dir,  "-C", self.acme_ca_pemfile])

    def get_apxs_var(self, name: str) -> str:
        p = subprocess.run([self._apxs, "-q", name], capture_output=True, text=True)
        if p.returncode != 0:
            return ""
        return p.stdout.strip()

    @property
    def apxs(self) -> str:
        return self._apxs

    @property
    def prefix(self) -> str:
        return self._prefix

    @property
    def mpm_type(self) -> str:
        return self._mpm_type

    @property
    def http_addr(self) -> str:
        return self._httpd_addr

    @property
    def http_port(self) -> int:
        return self._http_port

    @property
    def https_port(self) -> int:
        return self._https_port

    @property
    def proxy_port(self) -> int:
        return self._proxy_port

    @property
    def http_tld(self) -> str:
        return self._http_tld

    @property
    def domains(self) -> List[str]:
        return self._domains

    @property
    def expired_domains(self) -> List[str]:
        return self._expired_domains

    @property
    def http_base_url(self) -> str:
        return self._http_base

    @property
    def https_base_url(self) -> str:
        return self._https_base

    @property
    def test_src_dir(self) -> str:
        return self._test_src_dir

    @property
    def libexec_dir(self) -> str:
        return self._libexec_dir

    @property
    def server_conf_dir(self) -> str:
        return self._server_conf_dir

    @property
    def server_docs_dir(self) -> str:
        return self._server_docs_dir

    @property
    def store_dir(self) -> str:
        return self._store_dir

    @property
    def httpd_base_conf(self) -> List[str]:
        return self._httpd_base_conf

    @property
    def ssl_type(self) -> str:
        return self._ssl_type

    @property
    def a2md_bin(self):
        return self._a2md_bin

    @property
    def md_version(self):
        return self._md_version

    @property
    def acme_server(self):
        return self._acme_server

    @property
    def acme_url(self):
        return self._acme_url

    @property
    def acme_url_default(self):
        return self._acme_url_default

    @property
    def acme_ca_pemfile(self):
        return self._acme_ca_pemfile

    @property
    def acme_tos(self):
        return self._acme_tos

    @property
    def ca(self) -> Credentials:
        return self._ca

    def set_ca(self, ca: Credentials):
        self._ca = ca

    def get_credentials_for_name(self, dns_name) -> List['Credentials']:
        for domains in [self._domains, self._expired_domains]:
            if dns_name in domains:
                return self.ca.get_credentials_for_name(domains[0])
        return []

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

    def run(self, args, _input=None, debug_log=True):
        if debug_log:
            log.debug(f"run: {args}")
        start = datetime.now()
        p = subprocess.run(args, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        return ExecResult(exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr,
                          duration=datetime.now() - start)

    def a2md_stdargs(self, args):
        self._a2md_args = [] + args

    def a2md_rawargs(self, args):
        self._a2md_args_raw = [] + args

    def a2md(self, args, raw=False) -> ExecResult:
        preargs = self._a2md_args
        if raw:
            preargs = self._a2md_args_raw
        log.debug("running: {0} {1}".format(preargs, args))
        return self.run(preargs + args)

    def curl_complete_args(self, urls, timeout=None, options=None,
                           insecure=False, force_resolve=True):
        if not isinstance(urls, list):
            urls = [urls]
        u = urlparse(urls[0])
        assert u.hostname, f"hostname not in url: {urls[0]}"
        headerfile = f"{self.gen_dir}/curl.headers"
        if os.path.isfile(headerfile):
            os.remove(headerfile)
        args = [
            self._curl,
            "-s", "-D", headerfile,
        ]
        if u.scheme == 'http':
            pass
        elif insecure:
            args.append('--insecure')
        elif options and "--cacert" in options:
            pass
        elif u.hostname == self._default_domain:
            args.extend(["--cacert", f"{self.ca.cert_file}"])
        else:
            args.extend(["--cacert", self.acme_ca_pemfile])

        if force_resolve and u.hostname != 'localhost' \
                and u.hostname != self._httpd_addr \
                and not re.match(r'^(\d+|\[|:).*', u.hostname):
            assert u.port, f"port not in url: {urls[0]}"
            args.extend(["--resolve", f"{u.hostname}:{u.port}:{self._httpd_addr}"])
        if timeout is not None and int(timeout) > 0:
            args.extend(["--connect-timeout", str(int(timeout))])
        if options:
            args.extend(options)
        args += urls
        return args, headerfile

    def curl_raw(self, urls, timeout=10, options=None, insecure=False,
                 debug_log=True, force_resolve=True):
        args, headerfile = self.curl_complete_args(
            urls=urls, timeout=timeout, options=options, insecure=insecure,
            force_resolve=force_resolve)
        r = self.run(args, debug_log=debug_log)
        if r.exit_code == 0:
            lines = open(headerfile).readlines()
            exp_stat = True
            header = {}
            for line in lines:
                if exp_stat:
                    if debug_log:
                        log.debug("reading 1st response line: %s", line)
                    m = re.match(r'^(\S+) (\d+) (.*)$', line)
                    assert m
                    r.add_response({
                        "protocol": m.group(1),
                        "status": int(m.group(2)),
                        "description": m.group(3),
                        "body": r.outraw
                    })
                    exp_stat = False
                    header = {}
                elif re.match(r'^$', line):
                    exp_stat = True
                else:
                    m = re.match(r'^([^:]+):\s*(.*)$', line)
                    assert m
                    header[m.group(1).lower()] = m.group(2)
            r.response["header"] = header
            if r.json:
                r.response["json"] = r.json
        return r

    def curl_get(self, url, insecure=False, debug_log=True, options=None):
        return self.curl_raw(urls=[url], insecure=insecure,
                             options=options, debug_log=debug_log)

    # --------- HTTP ---------

    def install_test_conf(self, conf: List[str]):
        with open(self._test_conf, 'w') as fd:
            for line in self.httpd_base_conf:
                fd.write(f"{line}\n")
            for line in conf:
                fd.write(f"{line}\n")

    def is_live(self, url: str = None, timeout: timedelta = None):
        if url is None:
            url = self._http_base
        server = urlparse(url)
        if timeout is None:
            timeout = timedelta(seconds=5)
        try_until = datetime.now() + timeout
        last_err = ""
        while datetime.now() < try_until:
            # noinspection PyBroadException
            try:
                r = self.curl_get(url, insecure=True, debug_log=False)
                if r.exit_code == 0:
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
        log.debug(f"Unable to contact server after {timeout}")
        return False

    def is_dead(self, url: str = None, timeout: timedelta = None):
        if url is None:
            url = self._http_base
        server = urlparse(url)
        if timeout is None:
            timeout = timedelta(seconds=5)
        try_until = datetime.now() + timeout
        last_err = None
        while datetime.now() < try_until:
            # noinspection PyBroadException
            try:
                r = self.curl_get(url, debug_log=False)
                if r.exit_code != 0:
                    return True
                time.sleep(.1)
            except ConnectionRefusedError:
                log.debug("connection refused")
                return True
            except:
                if last_err != str(sys.exc_info()[0]):
                    last_err = str(sys.exc_info()[0])
                    log.debug("Unexpected error: %s", last_err)
                time.sleep(.1)
        log.debug(f"Server still responding after {timeout}")
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
        if self._acme_server_ok:
            return True
        if self._acme_server_down:
            pytest.skip(msg="ACME server not running")
            return False
        if self.is_live(self.acme_url, timeout=timedelta(seconds=0.5)):
            self._acme_server_ok = True
            return True
        else:
            self._acme_server_down = True
            pytest.fail(msg="ACME server not running", pytrace=False)
            return False

    def get_httpd_version(self):
        p = subprocess.run([self.apxs, "-q", "HTTPD_VERSION"], capture_output=True, text=True)
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
        log.debug("purge store dir: %s" % self._store_dir)
        assert len(self._store_dir) > 1
        if os.path.exists(self._store_dir):
            shutil.rmtree(self._store_dir, ignore_errors=False)
        os.makedirs(self._store_dir)

    def clear_store(self):
        log.debug("clear store dir: %s" % self._store_dir)
        assert len(self._store_dir) > 1
        if not os.path.exists(self._store_dir):
            os.makedirs(self._store_dir)
        for dirpath in ["challenges", "tmp", "archive", "domains", "accounts", "staging", "ocsp"]:
            shutil.rmtree(os.path.join(self._store_dir, dirpath), ignore_errors=True)

    def clear_ocsp_store(self):
        assert len(self._store_dir) > 1
        dirpath = os.path.join(self._store_dir, "ocsp")
        log.debug("clear ocsp store dir: %s" % dir)
        if os.path.exists(dirpath):
            shutil.rmtree(dirpath, ignore_errors=True)

    def authz_save(self, name, content):
        dirpath = os.path.join(self._store_dir, 'staging', name)
        os.makedirs(dirpath)
        open(os.path.join(dirpath, 'authz.json'), "w").write(content)

    def path_store_json(self):
        return os.path.join(self._store_dir, 'md_store.json')

    def path_account(self, acct):
        return os.path.join(self._store_dir, 'accounts', acct, 'account.json')

    def path_account_key(self, acct):
        return os.path.join(self._store_dir, 'accounts', acct, 'account.pem')

    def store_domains(self):
        return os.path.join(self._store_dir, 'domains')

    def store_archives(self):
        return os.path.join(self._store_dir, 'archive')

    def store_stagings(self):
        return os.path.join(self._store_dir, 'staging')

    def store_challenges(self):
        return os.path.join(self._store_dir, 'challenges')

    def store_domain_file(self, domain, filename):
        return os.path.join(self.store_domains(), domain, filename)

    def store_archived_file(self, domain, version, filename):
        return os.path.join(self.store_archives(), "%s.%d" % (domain, version), filename)

    def store_staged_file(self, domain, filename):
        return os.path.join(self.store_stagings(), domain, filename)

    def path_fallback_cert(self, domain):
        return os.path.join(self._store_dir, 'domains', domain, 'fallback-pubcert.pem')

    def path_job(self, domain):
        return os.path.join(self._store_dir, 'staging', domain, 'job.json')

    def replace_store(self, src):
        shutil.rmtree(self._store_dir, ignore_errors=False)
        shutil.copytree(src, self._store_dir)

    def list_accounts(self):
        return os.listdir(os.path.join(self._store_dir, 'accounts'))

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

    def _run_apachectl(self, cmd, conf=None):
        if conf:
            assert 1 == 0
        args = [self._apachectl, "-d", self.server_dir, "-k", cmd]
        p = subprocess.run(args, capture_output=True, text=True)
        self.apachectl_stderr = p.stderr
        rv = p.returncode
        if rv != 0:
            log.warning(f"exit {rv}, stdout: {p.stdout}, stderr: {p.stderr}")
        return rv

    def apache_restart(self, check_url: str = None):
        log.debug("restart apache")
        rv = self.apache_stop()
        rv = self._run_apachectl("start")
        if rv == 0:
            rv = 0 if self.is_live(url=check_url) else -1
        return rv

    def apache_start(self):
        return self.apache_restart()

    def apache_stop(self):
        log.debug("stop apache")
        self._run_apachectl("stop")
        return 0 if self.is_dead() else -1

    def apache_graceful_stop(self):
        log.debug("stop apache")
        self._run_apachectl("graceful-stop")
        return 0 if self.is_dead() else -1

    def apache_fail(self):
        log.debug("expect apache fail")
        self._run_apachectl("stop")
        rv = self._run_apachectl("start")
        if rv == 0:
            rv = 0 if self.is_dead() else -1
        else:
            rv = 0
        return rv

    def apache_error_log_clear(self):
        self.apachectl_stderr = ""
        if os.path.isfile(self._server_error_log):
            os.remove(self._server_error_log)

    RE_MD_RESET = re.compile(r'.*\[md:info].*initializing\.\.\.')
    RE_MD_ERROR = re.compile(r'.*\[md:error].*')
    RE_MD_WARN = re.compile(r'.*\[md:warn].*')

    def httpd_error_log_count(self, expect_errors=False, timeout_sec=5):
        ecount = 0
        wcount = 0
        end = datetime.now() + timedelta(seconds=timeout_sec)
        while datetime.now() < end:
            if os.path.isfile(self._server_error_log):
                fin = open(self._server_error_log)
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
            if not expect_errors or ecount + wcount > 0:
                return ecount, wcount
            time.sleep(.1)
        raise TimeoutError(f"waited {timeout_sec} sec for error/warnings to show up in log")

    def httpd_error_log_scan(self, regex):
        if not os.path.isfile(self._server_error_log):
            return False
        fin = open(self._server_error_log)
        for line in fin:
            if regex.match(line):
                return True
        return False

    RE_APLOGNO = re.compile(r'.*\[(?P<module>[^:]+):(error|warn)].* (?P<aplogno>AH\d+): .+')
    RE_ERRLOG_ERROR = re.compile(r'.*\[(?P<module>[^:]+):error].*')
    RE_ERRLOG_WARN = re.compile(r'.*\[(?P<module>[^:]+):warn].*')
    RE_NOTIFY_ERR = re.compile(r'.*\[urn:org:apache:httpd:log:AH10108:.+')
    RE_NO_RESPONDER = re.compile(r'.*has no OCSP responder URL.*')

    def apache_errors_and_warnings(self):
        errors = []
        warnings = []

        if os.path.isfile(self._server_error_log):
            for line in open(self._server_error_log):
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
                m = self.RE_NO_RESPONDER.match(line)
                if m:
                    # happens during testing
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

    def apache_errors_check(self):
        errors, warnings = self.apache_errors_and_warnings()
        assert (len(errors), len(warnings)) == (0, 0), \
            f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n" \
            "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))

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

    def get_http_status(self, domain, path, use_https=True):
        r = self.get_meta(domain, path, use_https, insecure=True)
        return r.response['status']

    def get_cert(self, domain, tls=None, ciphers=None):
        return MDCertUtil.load_server_cert(self._httpd_addr, self.https_port,
                                           domain, tls=tls, ciphers=ciphers)

    def get_server_cert(self, domain, proto=None, ciphers=None):
        args = [
            self._openssl, "s_client", "-status",
            "-connect", "%s:%s" % (self._httpd_addr, self.https_port),
            "-CAfile", self.acme_ca_pemfile,
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
            return MDCertUtil.parse_pem_cert(r.stdout)
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

    def get_meta(self, domain, path, use_https=True, insecure=False):
        schema = "https" if use_https else "http"
        port = self.https_port if use_https else self.http_port
        r = self.curl_get(f"{schema}://{domain}:{port}{path}", insecure=insecure)
        assert r.exit_code == 0
        assert r.response
        assert r.response['header']
        return r

    def get_content(self, domain, path, use_https=True):
        schema = "https" if use_https else "http"
        port = self.https_port if use_https else self.http_port
        r = self.curl_get(f"{schema}://{domain}:{port}{path}")
        assert r.exit_code == 0
        return r.stdout

    def get_json_content(self, domain, path, use_https=True, insecure=False,
                         debug_log=True):
        schema = "https" if use_https else "http"
        port = self.https_port if use_https else self.http_port
        url = f"{schema}://{domain}:{port}{path}"
        r = self.curl_get(url, insecure=insecure, debug_log=debug_log)
        if r.exit_code != 0:
            log.error(f"curl get on {url} returned {r.exit_code}"
                      f"\nstdout: {r.stdout}"
                      f"\nstderr: {r.stderr}")
        assert r.exit_code == 0, r.stderr
        return r.json

    def get_certificate_status(self, domain) -> Dict:
        return self.get_json_content(domain, "/.httpd/certificate-status", insecure=True)

    def get_md_status(self, domain, via_domain=None, use_https=True, debug_log=False) -> Dict:
        if via_domain is None:
            via_domain = self._default_domain
        return self.get_json_content(via_domain, f"/md-status/{domain}",
                                     use_https=use_https, debug_log=debug_log)

    def get_server_status(self, query="/", via_domain=None, use_https=True):
        if via_domain is None:
            via_domain = self._default_domain
        return self.get_content(via_domain, "/server-status%s" % query, use_https=use_https)

    def await_completion(self, names, must_renew=False, restart=True, timeout=60,
                         via_domain=None, use_https=True):
        try_until = time.time() + timeout
        renewals = {}
        names = names.copy()
        while len(names) > 0:
            if time.time() >= try_until:
                return False
            for name in names:
                mds = self.get_md_status(name, via_domain=via_domain, use_https=use_https)
                if mds is None:
                    log.debug("not managed by md: %s" % name)
                    return False

                if 'renewal' in mds:
                    renewal = mds['renewal']
                    renewals[name] = True
                    if 'finished' in renewal and renewal['finished'] is True:
                        if (not must_renew) or (name in renewals):
                            log.debug(f"domain cert was renewed: {name}")
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

    def await_error(self, domain, timeout=60, via_domain=None, use_https=True, errors=1):
        try_until = time.time() + timeout
        while True:
            if time.time() >= try_until:
                return False
            md = self.get_md_status(domain, via_domain=via_domain, use_https=use_https)
            if md:
                if 'state' in md and md['state'] == MDTestEnv.MD_S_ERROR:
                    return md
                if 'renewal' in md and 'errors' in md['renewal'] \
                        and md['renewal']['errors'] >= errors:
                    return md
            time.sleep(0.1)
        return None

    def await_file(self, fpath, timeout=60):
        try_until = time.time() + timeout
        while True:
            if time.time() >= try_until:
                return False
            if os.path.isfile(fpath):
                return True
            time.sleep(0.1)

    def check_file_permissions(self, domain):
        md = self.a2md(["list", domain]).json['output'][0]
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
        self.check_file_access(os.path.join(self._store_dir, 'accounts'), 0o755)
        self.check_file_access(os.path.join(self._store_dir, 'accounts', acct), 0o755)
        self.check_file_access(self.path_account(acct), 0o644)
        self.check_file_access(self.path_account_key(acct), 0o644)
        # staging
        self.check_file_access(self.store_stagings(), 0o755)

    def get_ocsp_status(self, domain, proto=None, cipher=None, ca_file=None):
        stat = {}
        args = [
            self._openssl, "s_client", "-status",
            "-connect", "%s:%s" % (self._httpd_addr, self.https_port),
            "-CAfile", ca_file if ca_file else self.acme_ca_pemfile,
            "-servername", domain,
            "-showcerts"
        ]
        if proto is not None:
            args.extend(["-{0}".format(proto)])
        if cipher is not None:
            args.extend(["-cipher", cipher])
        r = self.run(args, debug_log=False)
        ocsp_regex = re.compile(r'OCSP response: +([^=\n]+)\n')
        matches = ocsp_regex.finditer(r.stdout)
        for m in matches:
            if m.group(1) != "":
                stat['ocsp'] = m.group(1)
        if 'ocsp' not in stat:
            ocsp_regex = re.compile(r'OCSP Response Status:\s*(.+)')
            matches = ocsp_regex.finditer(r.stdout)
            for m in matches:
                if m.group(1) != "":
                    stat['ocsp'] = m.group(1)
        verify_regex = re.compile(r'Verify return code:\s*(.+)')
        matches = verify_regex.finditer(r.stdout)
        for m in matches:
            if m.group(1) != "":
                stat['verify'] = m.group(1)
        return stat

    def await_ocsp_status(self, domain, timeout=10, ca_file=None):
        try_until = time.time() + timeout
        while True:
            if time.time() >= try_until:
                break
            stat = self.get_ocsp_status(domain, ca_file=ca_file)
            if 'ocsp' in stat and stat['ocsp'] != "no response sent":
                return stat
            time.sleep(0.1)
        raise TimeoutError(f"ocsp respopnse not available: {domain}")

    def create_self_signed_cert(self, name_list, valid_days, serial=1000, path=None):
        dirpath = path
        if not path:
            dirpath = os.path.join(self.store_domains(), name_list[0])
        return MDCertUtil.create_self_signed_cert(dirpath, name_list, valid_days, serial)
