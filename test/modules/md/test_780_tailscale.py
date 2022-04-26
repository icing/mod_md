import os
import pytest

from .md_env import MDTestEnv
from .md_conf import MDConf


class TestTailscale:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        env.APACHE_CONF_SRC = "data/test_auto"
        acme.start(config='default')
        env.clear_store()
        MDConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    def _write_res_file(self, doc_root, name, content):
        if not os.path.exists(doc_root):
            os.makedirs(doc_root)
        open(os.path.join(doc_root, name), "w").write(content)

    # create a MD using `tailscale` as protocol
    def test_md_780_001(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain]
        socket_path = '/xxx'
        conf = MDConf(env, admin="admin@" + domain)
        conf.start_md(domains)
        conf.add([
            "MDCertificateProtocol tailscale",
            f"MDCertificateAuthority file://{socket_path}",
        ])
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        # restart and watch it fail due to wrong tailscale unix socket path
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['status-description'] == 'No such file or directory'
        assert md['renewal']['last']['detail'] == \
               f"tailscale socket not available, may not be up: {socket_path}"
