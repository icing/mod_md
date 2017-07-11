# test mod_md basic configurations

import os
import pytest
import re
import socket
import ssl
import sys
import time

from datetime import datetime
from httplib import HTTPSConnection
from testbase import TestEnv

def setup_module(module):
    print("setup_module    module:%s" % module.__name__)
    TestEnv.init()
    # TestEnv.apache_err_reset()
    TestEnv.APACHE_CONF_SRC = "data/roundtrip"
    # assert TestEnv.apachectl(None, "start") == 0
    
def teardown_module(module):
    print("teardown_module module:%s" % module.__name__)
    # status = TestEnv.apachectl(None, "stop")


class TestConf:


    @classmethod
    def setup_class(cls):
        cls.dns_uniq = "1499674813.org"

    """
    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)
        TestEnv.check_acme()
        # TestEnv.clear_store()

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)
    """

    # --------- add to store ---------

    """
    def test_100(self):
        # test case: 
        domain = "test200-" + TestConf.dns_uniq
        # assert TestEnv.apachectl("empty", "graceful") == 0
        assert TestEnv.is_live(TestEnv.HTTPD_URL, 5)
        # self._prepare_md([ domain ])
        assert self._tls_is_live("www."+ domain)

    # --------- _utils_ ---------

    def _prepare_md(self, dnsList):
        assert TestEnv.a2md(["add"] + dnsList)['rv'] == 0
        assert TestEnv.a2md(
            [ "update", dnsList[0], "contacts", "admin@" + dnsList[0] ]
            )['rv'] == 0
        assert TestEnv.a2md( 
            [ "update", dnsList[0], "agreement", TestEnv.ACME_TOS ]
            )['rv'] == 0
    """

    def _tls_is_live(self, domain):

        """"
        # CREATE SOCKET
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(60)

        sslCtx = ssl.create_default_context( purpose=ssl.Purpose.SERVER_AUTH, cafile=TestEnv.path_domain_ca_chain(domain) )
        # sslCtx = ssl.create_default_context( purpose=ssl.Purpose.SERVER_AUTH, cafile=None )
        sslSocket = sslCtx.wrap_socket(sock, server_side=False, do_handshake_on_connect=True, server_hostname=domain)
        # CONNECT AND PRINT REPLY
        sslSocket.connect(('localhost', int(TestEnv.HTTPS_PORT)))
        sslSocket.send("GET /hello.txt HTTP/1.1\r\n")
        sslSocket.send("Host: %s\r\n" % domain)
        print sslSocket.recv(1280)

        # CLOSE SOCKET CONNECTION
        sslSocket.close()
        """

        timeout = 2
        port = TestEnv.HTTPS_PORT
        caCert = TestEnv.path_domain_ca_chain(domain)
        print("Validate server using CA cert: %s" % caCert)
        try_until = time.time() + timeout
        sslCtx = ssl.create_default_context( purpose=ssl.Purpose.SERVER_AUTH, cafile=caCert )
        sslCtx.check_hostname = True
        sslCtx.verify_mode = ssl.CERT_OPTIONAL
        print("checking reachability of %s:%s" % (domain, port))
        while time.time() < try_until:
            try:
                c = HTTPSConnection(host="127.0.0.1", port=int(port), context=sslCtx, timeout=timeout)
                # c.set_tunnel(domain, int(port))
                c.set_debuglevel(1)
                c.connect()
                c.request('GET', "/hello.txt")
                resp = c.getresponse()
                c.close()
                return True
            except IOError:
                print "connect error:", sys.exc_info()
                time.sleep(.5)
            except:
                print "Unexpected error:", sys.exc_info()
                time.sleep(.5)
        print "Unable to contact server after %d sec" % timeout
        return False
