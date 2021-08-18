import os
from shutil import copyfile

from md_env import MDTestEnv


class HttpdConf(object):
    # Utility class for creating Apache httpd test configurations

    def __init__(self, env: MDTestEnv, name="test.conf", local_ca=True, text=None, std_ports=True,
                 std_vhosts=True, proxy=False):
        self.env = env
        self.path = os.path.join(env.GEN_DIR, name)
        if os.path.isfile(self.path):
            os.remove(self.path)
        with open(self.path, "a") as fd:
            fd.write("""
LoadModule {ssl}_module  "{prefix}/modules/mod_{ssl}.so"
LogLevel {ssl}:debug
LogLevel md:trace2    
            """.format(
                prefix=env.PREFIX,
                ssl=env.get_ssl_module(),
            ))
            if std_ports:
                fd.write("""
Listen {http_port}
Listen {https_port}

MDPortMap 80:{http_port} 443:{https_port}
                """.format(
                    http_port=env.HTTP_PORT,
                    https_port=env.HTTPS_PORT,
                ))
                if env.get_ssl_module() == "tls":
                    fd.write("""
    TLSListen {https_port}
                    """.format(
                        https_port=env.HTTPS_PORT,
                    ))
            if local_ca:
                fd.write("""
MDCertificateAuthority {acme_url}
MDCertificateAgreement accepted
MDCACertificateFile {webroot}/test-ca.pem
                """.format(acme_url=env.ACME_URL, webroot=env.WEBROOT)
                         )
            if std_vhosts:
                fd.write("""
include "conf/std_vhosts.conf"
                """)
            if proxy:
                fd.write("""
include "conf/proxy.conf"
    """)
            if text is not None:
                fd.write(text)

    def clear(self):
        if os.path.isfile(self.path):
            os.remove(self.path)

    def _add_line(self, line):
        open(self.path, "a").write(line + "\n")

    def add_line(self, line):
        self._add_line(line)

    def add_drive_mode(self, mode):
        self._add_line("  MDRenewMode \"%s\"\n" % mode)

    def add_renew_window(self, window):
        self._add_line("  MDRenewWindow %s\n" % window)

    def add_private_key(self, key_type, key_params):
        self._add_line("  MDPrivateKeys %s %s\n" % (key_type, " ".join(map(lambda p: str(p), key_params))))

    def add_admin(self, email):
        self._add_line("  ServerAdmin mailto:%s\n" % email)

    def add_md(self, domains):
        dlist = " ".join(domains)    # without quotes
        self._add_line(f"  MDomain {dlist}\n")

    def start_md(self, domains):
        dlist = " ".join([f"\"{d}\"" for d in domains])  # with quotes, #257
        self._add_line(f"  <MDomain {dlist}>\n")
        
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
        self._add_line("  MDRequireHttps \"%s\"\n" % mode)

    def add_notify_cmd(self, cmd):
        self._add_line("  MDNotifyCmd %s\n" % cmd)

    def add_message_cmd(self, cmd):
        self._add_line("  MDMessageCmd %s\n" % cmd)

    def add_dns01_cmd(self, cmd):
        self._add_line("  MDChallengeDns01 \"%s\"\n" % cmd)

    def add_certificate(self, cert_file, key_file):
        if self.env.get_ssl_module() == "ssl":
            self._add_line(f"""
                SSLCertificateFile {cert_file}
                SSLCertificateKeyFile {key_file}
                """)
        elif self.env.get_ssl_module() == "tls":
            self._add_line(f"""
                TLSCertificate {cert_file} {key_file}
            """)

    def add_vhost(self, domains, port=None, doc_root="htdocs"):
        self.start_vhost(domains, port=port, doc_root=doc_root)
        self.end_vhost()

    def add_ssl_vhost(self, domains, port=None, doc_root="htdocs", text=None):
        self.start_vhost(domains, port=port, doc_root=doc_root)
        if not port:
            port = self.env.HTTPS_PORT
        if text is not None:
            self.add_line(text)
        if self.env.get_ssl_module() == "ssl":
            self.add_line("    SSLEngine on\n")
        self.end_vhost()
        if self.env.get_ssl_module() == "tls":
            self.add_line("TLSListen {port}".format(port=port))

    def start_vhost(self, domains, port=None, doc_root="htdocs"):
        if not isinstance(domains, list):
            domains = [domains]
        if not port:
            port = self.env.HTTPS_PORT
        f = open(self.path, "a") 
        f.write("<VirtualHost *:%s>\n" % port)
        f.write("    ServerName %s\n" % domains[0])
        for alias in domains[1:]:
            f.write("    ServerAlias %s\n" % alias)
        f.write("    DocumentRoot %s\n\n" % doc_root)
        if self.env.HTTPS_PORT == port:
            if self.env.get_ssl_module() == "ssl":
                f.write("    SSLEngine on\n")
                  
    def end_vhost(self):
        self._add_line("</VirtualHost>\n\n")

    def install(self):
        copyfile(self.path, self.env.APACHE_TEST_CONF)
