import json
import logging
import os
import shutil
import subprocess
import time
from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta
from threading import Thread
from typing import Dict

from .md_env import MDTestEnv


log = logging.getLogger(__name__)


def monitor_proc(env: MDTestEnv, proc):
    _env = env
    proc.wait()


class ACMEServer:
    __metaclass__ = ABCMeta

    @abstractmethod
    def start(self):
        raise NotImplementedError

    @abstractmethod
    def stop(self):
        raise NotImplementedError

    @abstractmethod
    def install_ca_bundle(self, dest):
        raise NotImplementedError

    @abstractmethod
    def get_ari_for(self, ari_cert_id):
        raise NotImplementedError

    @abstractmethod
    def set_ari_for(self, domain):
        raise NotImplementedError


class MDPebbleRunner(ACMEServer):

    ACME_HOST = 'localhost:14000'
    MGMT_HOST = 'localhost:15000'

    def __init__(self, env: MDTestEnv, configs: Dict[str, str]):
        self.env = env
        self.configs = configs
        self._current = 'default'
        self._pebble = None
        self._challtestsrv = None
        self._log = None

    def start(self, config: str = None):
        if config is not None and config != self._current:
            # change, tear down and start again
            assert config in self.configs
            self.stop()
            self._current = config
        elif self._pebble is not None:
            # already running
            return
        args = ['pebble', '-config', self.configs[self._current], '-dnsserver', ':8053']
        env = {}
        env.update(os.environ)
        env['PEBBLE_VA_NOSLEEP'] = '1'
        self._log = open(f'{self.env.gen_dir}/pebble.log', 'w')
        self._pebble = subprocess.Popen(args=args, env=env,
                                        stdout=self._log, stderr=self._log)
        t = Thread(target=monitor_proc, args=(self.env, self._pebble))
        t.start()

        args = ['pebble-challtestsrv', '-http01', '', '-https01', '', '-tlsalpn01', '']
        self._challtestsrv = subprocess.Popen(args, stdout=self._log, stderr=self._log)
        t = Thread(target=monitor_proc, args=(self.env, self._challtestsrv))
        t.start()
        self.install_ca_bundle(self.env.acme_ca_pemfile)
        # disable ipv6 default address, this gives trouble inside docker
        end = datetime.now() + timedelta(seconds=5)
        while True:
            r = self.env.run(['curl', 'localhost:8055/'])
            if r.exit_code == 0:
                break
            if datetime.now() > end:
                raise TimeoutError(f'unable to contact pebble-challtestsrv on localhost:8055')
            time.sleep(.1)
        r = self.env.run(['curl', '-d', f'{{"ip":""}}',
                          'localhost:8055/set-default-ipv6'])
        assert r.exit_code == 0, f"{r}"

    def stop(self):
        if self._pebble:
            self._pebble.terminate()
            self._pebble = None
        if self._challtestsrv:
            self._challtestsrv.terminate()
            self._challtestsrv = None
        if self._log:
            self._log.close()
            self._log = None

    def install_ca_bundle(self, dest):
        shutil.copyfile(self.env.ca.cert_file, dest)
        end = datetime.now() + timedelta(seconds=20)
        while datetime.now() < end:
            r = self.env.curl_get('https://localhost:15000/roots/0', insecure=True)
            if r.exit_code == 0:
                with open(dest, 'a') as fd:
                    fd.write(r.stdout)
                break

    def get_ari_for(self, ari_cert_id):
        url = f'https://{self.ACME_HOST}/dir'
        r = self.env.curl_get(url, insecure=True)
        if r.exit_code != 0:
            log.error(f"curl get on {url} returned {r.exit_code}"
                      f"\nstdout: {r.stdout}"
                      f"\nstderr: {r.stderr}")
            return None
        assert r.json
        if 'renewalInfo' not in r.json:
            return None
        ari_url = f'{r.json["renewalInfo"]}/{ari_cert_id}'
        r = self.env.curl_get(ari_url, insecure=True)
        if r.exit_code != 0:
            log.error(f"curl get on {url} returned {r.exit_code}"
                      f"\nstdout: {r.stdout}"
                      f"\nstderr: {r.stderr}")
            return None
        assert r.json
        return r.json

    def set_ari_for(self, domain, ari):
        url = f'https://{self.MGMT_HOST}/set-renewal-info/'
        cert_file = self.env.store_domain_file(domain, 'pubcert.pem')
        assert os.path.exists(cert_file)
        req_json = {
            'Certificate': f'{open(cert_file).read()}',
            'ARIResponse': f'{json.JSONEncoder(indent="").encode(ari)}',
        }
        filename = os.path.join(self.env.gen_dir, f'set_ari_{domain}.tmp')
        with open(filename, 'w') as fd:
            fd.write(json.JSONEncoder(indent="").encode(req_json))
        return self.env.curl_post_json(url, f'@{filename}', options=['-vvv'])


class MDBoulderRunner(ACMEServer):

    def __init__(self, env: MDTestEnv):
        self.env = env
        self.install_ca_bundle(self.env.acme_ca_pemfile)

    def start(self, config=None):
        pass

    def stop(self):
        pass

    def install_ca_bundle(self, dest):
        r = self.env.run([
            'docker', 'exec', 'boulder_boulder_1', 'bash', '-c', "cat /tmp/root*.pem"
        ])
        assert r.exit_code == 0
        with open(dest, 'w') as fd:
            fd.write(r.stdout)
