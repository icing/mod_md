import logging
import os
import shutil
import subprocess
from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta
from threading import Thread

from md_env import MDTestEnv


log = logging.getLogger(__name__)

def monitor_proc(env: MDTestEnv, proc):
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


class MDPebbleRunner(ACMEServer):

    def __init__(self, env: MDTestEnv, config_file: str):
        self.env = env
        self.config_file = config_file
        self._pebble = None
        self._challtestsrv = None
        self._log = None

    def start(self):
        args = ['pebble', '-config', self.config_file, '-dnsserver', ':8053']
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
            r = self.env.curl_get('https://localhost:15000/roots/0', insecure=True, debug_log=False)
            if r.exit_code == 0:
                with open(dest, 'a') as fd:
                    fd.write(r.stdout)
                break


class MDBoulderRunner(ACMEServer):

    def __init__(self, env: MDTestEnv):
        self.env = env
        self.install_ca_bundle(self.env.acme_ca_pemfile)

    def start(self):
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

