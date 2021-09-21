import logging
import os
import time
from datetime import timedelta

import pytest

from md_certs import CertificateSpec, MDTestCA
from md_conf import HttpdConf
from md_env import MDTestEnv
from md_acme import MDPebbleRunner, MDBoulderRunner


def pytest_report_header(config, startdir):
    env = MDTestEnv()
    return "mod_md: {version} [apache: {aversion}({prefix}), mod_{ssl}, ACME server: {acme}]".format(
        version=env.md_version,
        prefix=env.prefix,
        aversion=env.get_httpd_version(),
        ssl=env.get_ssl_type(),
        acme=env.acme_server,
    )


@pytest.fixture(scope="session")
def env(pytestconfig) -> MDTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = MDTestEnv(pytestconfig=pytestconfig)
    env.apache_error_log_clear()
    cert_specs = [
        CertificateSpec(domains=['localhost'], key_type='rsa2048'),
        CertificateSpec(domains=env.domains, key_type='rsa4096'),
        CertificateSpec(domains=env.expired_domains, key_type='rsa2048',
                        valid_from=timedelta(days=-91),
                        valid_to=timedelta(days=-1)),
    ]
    ca = MDTestCA.create_root(name=env.http_tld,
                              store_dir=os.path.join(env.server_dir, 'ca'), key_type="rsa4096")
    ca.issue_certs(cert_specs)
    env.set_ca(ca)
    return env


@pytest.fixture(autouse=True, scope="session")
def _session_scope(env):
    acme_server = None
    if env.acme_server == 'pebble':
        pebble_conf = os.path.join(env.server_dir, 'conf/pebble.json')
        acme_server = MDPebbleRunner(env, config_file=pebble_conf)
    elif env.acme_server == 'boulder':
        acme_server = MDBoulderRunner(env)
    if acme_server is not None:
        acme_server.start()
    yield
    if acme_server is not None:
        acme_server.stop()
    HttpdConf(env).install()
    assert env.apache_stop() == 0
    #env.apache_errors_check()
