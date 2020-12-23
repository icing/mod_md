###################################################################################################
# httpd test configuration generator
#
# (c) 2019 greenbytes GmbH
###################################################################################################

import os
from shutil import copyfile

from TestEnv import TestEnv


class HttpdConf(object):
    # Utility class for creating Apache httpd test configurations

    def __init__(self, name="test.conf", local_ca=True, text=None, std_vhosts=True, proxy=False):
        self.path = os.path.join(TestEnv.GEN_DIR, name)
        if os.path.isfile(self.path):
            os.remove(self.path)
        if not text:
            text = """
LogLevel md:trace2
LogLevel ssl:debug
                
                """
            
        if local_ca:
            text = """
MDCertificateAuthority %s
MDCertificateAgreement accepted
MDCACertificateFile %s/test-ca.pem
                
%s
""" % (TestEnv.ACME_URL, TestEnv.WEBROOT, text)

        if std_vhosts:
            text = """
Listen %s
Listen %s

MDPortMap 80:%s 443:%s
                
include "conf/std_vhosts.conf"
                
%s
""" % (TestEnv.HTTP_PORT, TestEnv.HTTPS_PORT, TestEnv.HTTP_PORT, TestEnv.HTTPS_PORT, text)

        if proxy:
            text = """
include "conf/proxy.conf"
                
%s
""" % text
        open(self.path, "a").write(text)

    def clear(self):
        if os.path.isfile(self.path):
            os.remove(self.path)

    def _add_line(self, line):
        open(self.path, "a").write(line + "\n")

    def add_line(self, line):
        self._add_line(line)

    def add_drive_mode(self, mode):
        self._add_line("  MDRenewMode %s\n" % mode)

    def add_renew_window(self, window):
        self._add_line("  MDRenewWindow %s\n" % window)

    def add_private_key(self, key_type, key_params):
        self._add_line("  MDPrivateKeys %s %s\n" % (key_type, " ".join(map(lambda p: str(p), key_params))))

    def add_admin(self, email):
        self._add_line("  ServerAdmin mailto:%s\n\n" % email)

    def add_md(self, domains):
        self._add_line("  MDomain %s\n\n" % " ".join(domains))

    def start_md(self, domains):
        self._add_line("  <MDomain %s>\n" % " ".join(domains))
        
    def start_md2(self, domains):
        self._add_line("  <MDomainSet %s>\n" % " ".join(domains))

    def end_md(self):
        self._add_line("  </MDomain>\n")

    def end_md2(self):
        self._add_line("  </MDomainSet>\n")

    def add_must_staple(self, mode):
        self._add_line("  MDMustStaple %s\n" % mode)

    def add_ca_challenges(self, type_list):
        self._add_line("  MDCAChallenges %s\n" % " ".join(type_list))

    def add_http_proxy(self, url):
        self._add_line("  MDHttpProxy %s\n" % url)

    def add_require_ssl(self, mode):
        self._add_line("  MDRequireHttps %s\n" % mode)

    def add_notify_cmd(self, cmd):
        self._add_line("  MDNotifyCmd %s\n" % cmd)

    def add_message_cmd(self, cmd):
        self._add_line("  MDMessageCmd %s\n" % cmd)

    def add_dns01_cmd(self, cmd):
        self._add_line("  MDChallengeDns01 %s\n" % cmd)

    def add_vhost(self, domains, port=None, doc_root="htdocs"):
        self.start_vhost(domains, port=port, doc_root=doc_root)
        self.end_vhost()

    def start_vhost(self, domains, port=None, doc_root="htdocs"):
        if not isinstance(domains, list):
            domains = [domains]
        if not port:
            port = TestEnv.HTTPS_PORT 
        f = open(self.path, "a") 
        f.write("<VirtualHost *:%s>\n" % port)
        f.write("    ServerName %s\n" % domains[0])
        for alias in domains[1:]:
            f.write("    ServerAlias %s\n" % alias)
        f.write("    DocumentRoot %s\n\n" % doc_root)
        if TestEnv.HTTPS_PORT == port:
            f.write("    SSLEngine on\n")
                  
    def end_vhost(self):
        self._add_line("</VirtualHost>\n\n")

    def install(self):
        copyfile(self.path, TestEnv.APACHE_TEST_CONF)
