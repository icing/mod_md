import logging
import os
import sys
from datetime import timedelta
import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from .md_certs import CertificateSpec, MDTestCA
from .md_conf import HttpdConf
from .md_env import MDTestEnv
from .md_acme import MDPebbleRunner, MDBoulderRunner


def pytest_report_header(config, startdir):
    env = MDTestEnv()
    return "mod_md: [apache: {aversion}({prefix}), mod_{ssl}, ACME server: {acme}]".format(
        prefix=env.prefix,
        aversion=env.get_httpd_version(),
        ssl=env.get_ssl_type(),
        acme=env.acme_server,
    )


@pytest.fixture(scope="package")
def env(pytestconfig) -> MDTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = MDTestEnv(pytestconfig=pytestconfig)
    env.apache_access_log_clear()
    env.apache_error_log_clear()
    return env


@pytest.fixture(autouse=True, scope="package")
def _session_scope(env):
    yield
    # HttpdConf(env).install()
    assert env.apache_stop() == 0
    errors, warnings = env.apache_errors_and_warnings()
    assert (len(errors), len(warnings)) == (0, 0),\
            f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n"\
            "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))


@pytest.fixture(scope="package")
def acme(env):
    acme_server = None
    if env.acme_server == 'pebble':
        acme_server = MDPebbleRunner(env, configs={
            'default': os.path.join(env.gen_dir, 'pebble/pebble.json'),
            'eab': os.path.join(env.gen_dir, 'pebble/pebble-eab.json'),
        })
    elif env.acme_server == 'boulder':
        acme_server = MDBoulderRunner(env)
    yield acme_server
    if acme_server is not None:
        acme_server.stop()

