# Testing Apache ACME

There are many platforms where Apache httpd is available. This document keeps
focus on a modern Linux distribution, such as `debian sid`.

## Installation

Debian's package manager `apt` offers the latest Apache httpd version. You can install
this simply via 

```
> sudo apt install apache2  libapache2-mod-md
> sudo a2enmod md
> sudo a2enmod watchdog
> sudo systemctl reload apache2
```

This enabled the ACME module `mod_md` and the needed `watchdog` module. From there on
its configuring your Apache to actually use ACME, which is covered below.

### From github

If you want to test the latest version from github, you need a bit more infrastructure
to build the module's source. At the minimum you will need:

```
> apt install make openssl libssl-dev libcurl4 libcurl4-openssl-dev \
      gcc git libapr1-dev libaprutil1-dev \
      autoconf libtool libtool-bin libpcre3-dev libjansson-dev curl \
      apache2 apache2-dev
```

With that, you can make a clone of the repository and build it:

```
> git clone git@github.com:icing/mod_md.git
> cd mod_md
mod_md> autoreconf -i
mod_md> ./configure
mod_md> make
mod_md> sudo make install
```

and you have the current module built and deployed. Reload the server and it will be active.

## Configurations

### Public ACME Server

If you want to test against a public ACME server, such as the one from Let's Encrypt, there
are many recipes available on the [README](../README.md). These should explain how to configure
your domains and virtual hosts for automated certificates.

### Private ACME Server

To test with a private ACME server, you need to configure Apache on where to find it. Make
a new configuration file in your apache installation:

```
> sudo touch /etc/apache2/conf-available/my-acme.conf
> sudo a2enconf my-acme
```

Now, assuming you want a certificate for the domain `test1.mydomain.org` and have
your ACME server available at `my-acme-server.mydomain.org`. 
Use your text editor of choice to place the following content into `my-acme.conf`:

```
# The ACME server at my-acme-server.mydomain.org has endpoint /directory
MDCertificateAuthority https://my-acme-server.mydomain.org/directory
MDCertificateAgreement accepted
# if the server uses external account binding, add it
MDExternalAccountBinding <key-id> <hmac-value>

<MDomain test1.mydomain.org>
  MDRenewMode always
</MDomain>

```
To make this active, reload the server:

```
> sudo systemctl reload apache2
```

Apache will notice that it needs to manage the domain `test1.mydomain.org` and that
it does not have a certificate for it. It will immediately start to contact the ACME
server at `https://my-acme-server.mydomain.org/directory` and start the certificate
request.

You can see that it has now created some directories in your file system:

```
> ls /etc/apache2/md
accounts  archive  challenges  domains  md_store.json  ocsp  staging  tmp
> ls /etc/apache2/md/staging
test1.mydomain.org
> sudo ls /etc/apache2/md/staging/test1.mydomain.org
job.json  md.json  privkey.pem	pubcert.pem
```

A directory beneath `staging` is created when a domain needs new certificates. That
directory may not be readable by everyone, so use `sudo` to view it with special
privileges.

The file `md.json` contains the settings for the managed domain. In `job.json`
you will find information about the certificate renewal. What the module did
and how the ACME server answered.

The files `privkey.pem` and `pubcert.pem` are created when the ACME server was
happy and issued a certificate. If that was indeed the case, you can activate it
by reloading the server.

```
> sudo systemctl reload apache2
> ls /etc/apache2/md/staging
# nothing listed
> ls /etc/apache2/md/domains
ls: cannot open directory '/etc/apache2/md/domains': Permission denied
> sudo ls /etc/apache2/md/domains
test1.mydomain.org
> sudo ls /etc/apache2/md/domains/test1.mydomain.org
job.json  md.json  privkey.pem	pubcert.pem
```

The server moved the files from `staging` into `domains` and applied more restrictive
permissions. From there, it is used in virtual hosts where needed. To do this, add

```
<VirtualHost *:443>
  ServerName test1.mydomain.org
  SSLEngine on
</VirtualHost>
```

to your config and reload the server again.

### Troubleshooting

When the configuration does not work as expected, the following checks will be useful:

1. Has a directory in `/etc/apache2/md/staging` been created?
1. If yes, what does the `job.json` file contain? Was your ACME server contacted? Did it
    return some errors?
1. If the job file does not really help, or the reason for reported errors is not obvious,
  you need to dig deeper. For this, you should raise the log level for the `md` module.
  Add to your configuration:
  
```
LogLevel md:trace2
```
And reload the server. Exactly was is happening is now logged in detail in the standard
error log of Apache. This can be found at `/var/log/apache2/error.log`.

In case something is really obscure, you can raise the log level even further to `trace4`
and see HTTP requests and responses exchanged between Apache and your ACME server.

The most common problems encountered are mistakes in the configuration and the network
setup:

1. Can your Apache reach the ACME server?
2. Can your ACME server reach your Apache?
3. Is your Apache reachable on port 80 and 443 for http: and https:?
4. Do you have special requirements for Trust Anchors, e.g. root certificates?

Again, several topics in regard to this are also covered in the [README](../README.md)
as they apply also for public ACME servers.
