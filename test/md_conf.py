from md_env import MDTestEnv


class HttpdConf(object):
    # Utility class for creating Apache httpd test configurations

    def __init__(self, env: MDTestEnv, text=None, std_ports=True,
                 local_ca=True, std_vhosts=True, proxy=False,
                 admin=None):
        self.env = env
        self._indents = 0
        self._lines = []

        if admin is None:
            admin = f"admin@{env.http_tld}"
        if len(admin.strip()):
            self.add_admin(admin)

        if local_ca:
            self.add([
                f"MDCertificateAuthority {env.acme_url}",
                f"MDCertificateAgreement accepted",
                f"MDCACertificateFile {env.server_dir}/acme-ca.pem",
                "",
                ])

        if std_ports:
            self.add([
                f"Listen {env.http_port}",
                f"Listen {env.https_port}",
                f"MDPortMap 80:{env.http_port} 443:{env.https_port}",
                "",
            ])
            if env.ssl_type == "tls":
                self.add([
                    f"TLSListen {env.https_port}",
                ])
        if std_vhosts:
            self.add_vhost(domains=env.domains, port=env.http_port)
            self.start_vhost(domains=env.domains, port=env.https_port)
            for cred in self.env.get_credentials_for_name(env.domains[0]):
                self.add_certificate(cred.cert_file, cred.pkey_file)
            self.end_vhost()
        if proxy:
            self.add("include conf/proxy.conf")
        if text is not None:
            self.add(text)

    def clear(self):
        self._lines = []

    def add(self, line):
        if isinstance(line, list):
            if self._indents > 0:
                line = [f"{'  ' * self._indents}{l}" for l in line]
            self._lines.extend(line)
        else:
            if self._indents > 0:
                line = f"{'  ' * self._indents}{line}"
            self._lines.append(line)
        return self

    def add_drive_mode(self, mode):
        self.add("MDRenewMode \"%s\"\n" % mode)

    def add_renew_window(self, window):
        self.add("MDRenewWindow %s\n" % window)

    def add_private_key(self, key_type, key_params):
        self.add("MDPrivateKeys %s %s\n" % (key_type, " ".join(map(lambda p: str(p), key_params))))

    def add_admin(self, email):
        self.add(f"ServerAdmin mailto:{email}")

    def add_md(self, domains):
        dlist = " ".join(domains)    # without quotes
        self.add(f"MDomain {dlist}\n")

    def start_md(self, domains):
        dlist = " ".join([f"\"{d}\"" for d in domains])  # with quotes, #257
        self.add(f"<MDomain {dlist}>\n")
        
    def start_md2(self, domains):
        self.add("<MDomainSet %s>\n" % " ".join(domains))

    def end_md(self):
        self.add("</MDomain>\n")

    def end_md2(self):
        self.add("</MDomainSet>\n")

    def add_must_staple(self, mode):
        self.add("MDMustStaple %s\n" % mode)

    def add_ca_challenges(self, type_list):
        self.add("MDCAChallenges %s\n" % " ".join(type_list))

    def add_http_proxy(self, url):
        self.add("MDHttpProxy %s\n" % url)

    def add_require_ssl(self, mode):
        self.add("MDRequireHttps \"%s\"\n" % mode)

    def add_notify_cmd(self, cmd):
        self.add("MDNotifyCmd %s\n" % cmd)

    def add_message_cmd(self, cmd):
        self.add("MDMessageCmd %s\n" % cmd)

    def add_dns01_cmd(self, cmd):
        self.add("MDChallengeDns01 \"%s\"\n" % cmd)

    def add_certificate(self, cert_file, key_file):
        if self.env.ssl_type == "ssl":
            self.add([
                f"SSLCertificateFile {cert_file}",
                f"SSLCertificateKeyFile {key_file}",
            ])
        elif self.env.ssl_type == "tls":
            self.add(f"""
                TLSCertificate {cert_file} {key_file}
            """)

    def add_vhost(self, domains, port=None, doc_root="htdocs"):
        self.start_vhost(domains, port=port, doc_root=doc_root)
        self.end_vhost()

    def add_ssl_vhost(self, domains, port=None, doc_root="htdocs", text=None):
        self.start_vhost(domains, port=port, doc_root=doc_root)
        if not port:
            port = self.env.https_port
        if text is not None:
            self.add(text)
        if self.env.ssl_type == "ssl":
            self.add("SSLEngine on")
        self.end_vhost()
        if self.env.ssl_type == "tls":
            self.add("TLSListen {port}".format(port=port))

    def start_vhost(self, domains, port=None, doc_root="htdocs"):
        if not isinstance(domains, list):
            domains = [domains]
        if not port:
            port = self.env.https_port
        self.add(f"<VirtualHost *:{port}>")
        self._indents += 1
        self.add(f"ServerName {domains[0]}")
        for alias in domains[1:]:
            self.add(f"ServerAlias {alias}")
        self.add(f"DocumentRoot {doc_root}")
        if self.env.https_port == port and self.env.ssl_type == "ssl":
            self.add("SSLEngine on")
                  
    def end_vhost(self):
        self._indents -= 1
        self.add([
            "</VirtualHost>",
            "",
        ])

    def install(self):
        self.env.install_test_conf(self._lines)
