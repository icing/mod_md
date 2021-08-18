import logging

import pytest

from md_env import MDTestEnv


def pytest_report_header(config, startdir):
    env = MDTestEnv()
    return "mod_md: {version} [apache: {aversion}({prefix}), mod_{ssl}]".format(
        version=env.A2MD_VERSION,
        prefix=env.PREFIX,
        aversion=env.get_httpd_version(),
        ssl=env.get_ssl_module(),
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
    return env

@pytest.fixture(autouse=True, scope="session")
def _session_scope(env):
    yield
    assert env.apache_stop() == 0
    errors, warnings = env.apache_errors_and_warnings()
    assert (len(errors), len(warnings)) == (0, 0),\
            f"apache logged {len(errors)} errors and {len(warnings)} warnings: \n"\
            "{0}\n{1}\n".format("\n".join(errors), "\n".join(warnings))

