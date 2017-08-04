
# mod_md - Everybody Spies

Copyright 2017 greenbytes GmbH

This repository contains `mod_md`, a module for Apache httpd that adds support for Let's Encrypt (and other ACME CAs). 

This code here is to help people review and comment and test before I bring it into the main Apache httpd repository. Issues you can raise here, general discussion is probably best at the httpd dev mailing list.

## What can I expect?

When you have installed ```mod_md``` and the patched ```mod_ssl``` in your Apache
and configured ```your_domain``` to be managed (how, I explain more below), you will
see something like the following in your log file:

```
[...00.587735] [md:info] ...<your_domain>: setup staging
[...00.588024] [md:info] ...<your_domain>: need certificate
[...07.040614] [md:info] ...<your_domain>: check Terms-of-Service agreement
[...07.040692] [md:info] ...<your_domain>: setup new authorization
[...13.604130] [md:info] ...<your_domain>: setup new challenges
[...19.522348] [md:info] ...<your_domain>: monitoring challenge status
[...25.387469] [md:info] ...<your_domain>: checked all domain authorizations
[...25.387551] [md:info] ...<your_domain>: creating certificate request
[...35.480524] [md:info] ...<your_domain>: received certificate
[...35.480565] [md:info] ...<your_domain>: retrieving certificate chain
[...41.634865] [md:notice] ... 1 Managed Domain has been setup and 
               changes will be activated on next (graceful) server restart.
```

when you then restart the server, the new Let's Encrypt certificate is used by ```your_domain```. Before it expires, ```mod_md``` will obtain a new one and you will see a similar message in your server log.

## What do I need to do?

Apart from the installation, you need to configure your server to load ```mod_md``` and tell it where it should take over your ```https``` management. A simple example:

You have a virtual host defined like this:

```
<VirtualHost *:443>
    ServerName www.your_domain.de
    ServerAlias your_domain.de
    Protocols h2 http/1.1

    SSLEngine on
    SSLCertificateFile /etc/mycerts/your_domain.de/fullchain.pem
    SSLCertificateKeyFile /etc/mycerts/your_domain.de/privkey.pem
    ...
</VirtualHost>
```
then you could change it to this:

```
ManagedDomain your_domain.de www.your_domain.de

<VirtualHost *:443>
    ServerName www.your_domain.de
    ServerAlias your_domain.de
    Protocols h2 http/1.1

    SSLEngine on
    ...
</VirtualHost>
```
The ```SSLCertificate*``` configurations are gone and you added a ```ManagedDomain``` with a list of host names (here, there are two, it could be just one or maybe ten).

More examples and other documentation you can find [on the wiki](https://github.com/icing/mod_md/wiki).

## Status

***NEW***: the Apache2 PPA for ubuntu by @oerdnj, see [here](https://launchpad.net/~ondrej/+archive/ubuntu/apache2/+packages), has a patched ```mod_ssl``` just as ```mod_md``` needs it! Thanks! So, in such a server you just need to drop mod_md from here.

***v0.4.0:*** I have tested that version on ubuntu 14.04 with the PPA from @oerdnj on my live server against the read Let's Encrypt service. The first green lock in the browser, managed by ```mod_md```. We're getting close!

What you find here are **early experience versions** for people who like living on the edge and want to help me test not yet released changes.

This is not _checkout, configure and shoot_. For it to work, you need a patched mod_ssl (patch is provided in directory ```patches```), but that is about the only complication.

Also: this is not production ready, yet. There is an ever expanding test suite included against a local [boulder](https://github.com/letsencrypt/boulder) server, using the excellent [pytest](https://docs.pytest.org/en/latest/). Also, thanks to Jacob Champion, we have unit tests available when [check](https://libcheck.github.io/check/) is installed.

For more about about use and limitations, see [Usage](#usage) below.

### Test Status

Tests have been verfied to run on MacOS and Ubuntu 16.04 under the following conditions:

 * the *SSL library you compile with supports ```SNI``` 
 * curl is linked against this recent *SSL lib
 * your Apache httpd installation has a patched ```mod_ssl```
 * you have a local boulder server installed and it resolved host names against your httpd (see below)

So, it's a bit tricky when your OS does not support features like ```SNI``` in its standard config.

## Install

You need a built Apache httpd 2.4.x or trunk, including apxs and headers to compile and 
run this module. Additionally, you need an installed libjansson and libcurl. 
And additionally, you want an installed OpenSSL >=1.0.2, where libcurl is built
against. It may work with other *SSL libraries, however I have not verified that. 

To run the tests, you need [pytest](https://docs.pytest.org/en/latest/), [PyOpenSSL](https://pyopenssl.org/en/stable/),  and a local [boulder](https://github.com/letsencrypt/boulder) installation (I use the docker one they provide. Read the instructions in their excellent documentation). The instance I run via

```
docker-compose run -e FAKE_DNS=192.168.1.65 --service-ports boulder ./start.py 
```
where ```192.168.1.65``` is the address my Apache httpd is listening on.

When running the tests, make sure your Docker instance is able to access ports
5001 and 5002 on the host.

## Changes

See ```ChangeLog``` for details.

## Build from git

Still not dissuaded? Ok, here are some hints to get you started.
Building from git is easy, but please be sure that at least autoconf 2.68 is
used:

```
> autoreconf -i
> automake
> autoconf
> ./configure --with-apxs=<path to apxs>
> make
```

## Usage

When all is done as I would like it to be, you just add a single line to your Apache config and that's it. Suppose you own the domains ```example.org``` and ```www.example.org``` and have an Apache reachable under this domain, then you'd add

```
  ManagedDomain example.org www.example.org
```
to your Apache configuration and ```mod_md``` will get you a certificate from Let's Encrypt, install it in your file system and restart the server to activate it. It will the peridically 
check if all is fine and, 14 days before the certificate expires, get you a new one.

(***Attention:*** before you head off and add this to your server, see the list of current [limitations](#limitations)! Also, by ***default right now*** certificates are retrieved from the Let's Encrypt _staging_ environment. Which is a playground. When this thing really gets production ready, I will change  this default. Now you need to do that explicitly, if you feel so brave. See under ***Advanced Usage***)

(***More Attention:*** if you want to play around with this now, nothing will work until you agree to Let's Encrypt's [Terms of Service](#terms-of-service) and give a [Contact Email Address](#contact-information).

Of course, you still need to configure a ```VirtualHost``` (or several) for it that defines which resources/applications are served and what security restrictions you have etc. So, a more complete config example would look like this:

```
  ManagedDomain example.org www.example.org
  
  <VirtualHost *:443>
    ServerName example.org
    ServerAlias www.example.org
    
    SSLEngine on
    # no certificates specification needed!
    
    ...
  </VirtualHost>
```
You can define one Managed Domain for many names and hosts, such as:

```
  ManagedDomain a.example.org b.another.com
  
  <VirtualHost *:443>
    ServerName a.example.org
    
    ...
  </VirtualHost>

  <VirtualHost *:443>
    ServerName b.another.com
    
    ...
  </VirtualHost>
```
and ```mod_md``` will retrieve one certificate that works for both of them.

You want to use that certificate also for you mail server? Just add its domain name and the certificate will also be made to work for that one. The names you specify as ```ManagedDomain``` do not have to be _all_ used by your web server (caveat: if none is used, ```mod_md``` will be lazy and skip it).

Also, you do not _have to_ use the same certificate:

```
  ManagedDomain a.example.org
  ManagedDomain b.another.com
  
  <VirtualHost *:443>
    ServerName a.example.org
    
    ...
  </VirtualHost>

  <VirtualHost *:443>
    ServerName b.another.com
    
    ...
  </VirtualHost>
```
will create two separate certificates.

### Terms of Service

When you use ```mod_md``` you become a customer of the CA (e.g. Let's Encrypt) and that means you need to read and agree to their Terms of Service, so that you understand what they offer and what they might exclude or require from you. It's a legal thing.

```mod_md``` cannot, by itself, agree to such a thing. ***You*** need to agree to it. For your convenience, you can tell ```mod_md``` that it should tell the CA that you agree. You do that by configuring:

```
MDCertificateAgreement <url-of-terms-of-service>
```
In case of Let's Encrypt, their current [Terms of Service are here](https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf). Those terms might (and probably will) change over time. So, the certificate renewal might require you to update this agreement URL.

### Contact Information

Also, the ACME protocol requires you to give a contact url when you sign up. Currently, Let's Encrypt wants an email address (and it will use it to inform you about renewals or changed terms of service). ```mod_md``` uses the ```ServerAdmin``` email in your Apache configuration, so please specify the correct address there.

## Advanced Usage

### Certificate Authority and Protocol

The configuration directives
  * ```MDCertificateAuthority``` gives the URL where the certificate protocol can be reached.
  * ```MDCertificateProtocol``` specifies the protocol used (only ```ACME``` supported for now)

The default now is

```
MDCertificateAuthority  https://acme-staging.api.letsencrypt.org/directory
MDCertificateProtocol   ACME
```
When this becomes production ready, the default will be changed to ```https://acme-v01.api.letsencrypt.org/directory``` which hands out _real_ certificates.

### Drive Mode

```mod_md``` calls it _driving_ a protocol/domain to obtain the certificates. And there are two separate modes, the default being:

```
MDDriveMode  auto
```
where, unsurprisingly, ```mod_md``` will do its best to automate everything. The other mode is ```manual``` where mod_md will not contact the CA itself. Instead, you may use the provided command line utility ```a2md``` to perform this - separate from your httpd process.

(***Note***: ```auto``` drive mode requires ```mod_watchdog``` to be active in your server.)

### When to Renew

Normally, certificates are valid for around 90 days and ```mod_md``` will renew them the earliest 14 days before they expire. If you think this is too close, you can specify the number of days, as in:

```
MDRenewWindow   21d
```
or as in

```
MDRenewWindow   30s
```
but 30 seconds might be cutting things a little close.

### When and how often does it check?

When in ```auto``` drive mode, the module will check every 12 hours at least what the status of the managed domains is and if it needs to do something. On errors, for example when the CA is unreachable, it will initially retry after some seconds. Should that continue to fail, it will back off to a maximum interval of hourly checks.

***It will contact no outside server at startup!*** All driving is done when the server is running and serving traffic. There is nothing that delays the startup/restart of your httpd.

If a Managed Domain does not have all information, it will answer all requests with a ```503 Service Unavailable``` - assuming your client even wants to talk to it (it might fall back to another vhost TLS definition, depending how you server is setup).

Expired certificates will continue being used until a replacement is available. So, when your server clock freaks out, nothing gets thrown away automatically. Also, speaking of throwing things away: ```mod_md``` keeps a copy of previous certificates/keys when it renews a domain. You have those files as part of your backups, right?

### MD Specific Settings

All the configuration settings discussed so far should be done in the global server configuration. But you can still make settings _specific_ to a particular Managed Domain:

```
<ManagedDomain example.org>
    MDMember www.example.org
    MDDriveMode manual
    MDCertificateAuthority   https://someotherca.com/ACME
</ManagedDomain>
```
This allows you to have one domain from Let's Encrypt and a second from some other provider. Or also Let's Encrypt, but using another protocol (version).

## Storage

By default, ```mod_md``` stores its data in ```<ServerRoot>/md```. Sensitive data has its access permissions either restricted (if the platform supports it), or if read access by httpd child processes is necessary, private keys are encrypted using a shared secret.

(More to be written about how this works).

Underneath ```<ServerRoot>/md```, you will find:

 * ```domains/<name>```: which contains all files for the Managed Domain 'name' (the name of a managed domain is always the first domain you specified the first time).
 * ```accounts/<servername-nnn>```: data from your account at a CA
 * ```archive/<name.nnn>```: previous versions of domain data
 * ```challenges/<name>```: information to answer challenges from the CA
 * ```staging/<name>```: information collected during protocol driving
 * ```md_store.json```: store meta data and shared secret between httpd and its child processes

## Limitations

#### No VirtualHost Splitting, No Overlaps

A ManagedDomain ***must*** always cover all domain names used by a ```VirtualHost```(e.g. all names in ```ServerName``` and ```ServerAlias```). It can have additional names, or the names from several virtual hosts, but never less. That is the way Apache httpd works.

Also: Managed Domains cannot overlap. You may not specify the same name in two Managed Domains.

#### No Auto Restart when started as ```root```

When ```httpd``` is started as ```root``` user by your system, as most *NIX distribution set it up, it is configured to have its children (the ones doing the actual work) run as a quite restricted user. On Ubuntu, this is commonly ```www-data```. This is good for security, obviously.

```mod_md``` runs the ACME protocol also in these child processes and is therefore also restricted in the damages it can do. Which at the moment, also means it cannot signal the parent process to do a graceful restart. So, you will see a line in the error log that it was forbidden to do that. For now, in such a setup, you have to manually restart httpd for any certificate changes to take effect.

#### Need to be reachable on port 80

The ACME protocol _challenges_ your server to prove that it has control over the domains. There are several methods available. The ```http-01``` challenge works over port 80 (plain ```http:```) and the ```tls-sni-01``` works on port 443 (```https```). So far, only the first one is implemented by ```mod_md```. The other will come soon, however.

#### Need a patched ```mod_ssl```

Normally, you need to configure ```mod_ssl``` with ```SSLCertificateFile```, ```SSLCertificateKeyFile``` and ```SSLCertificateChainFile``` directive to tell it where to get this information it needs for the TLS protocol. You no longer need to do that now, as ```mod_md``` is in charge of these and will tell ```mod_ssl``` where to find them.

#### Other Platforms

I have only tested this on MacOS and Linux so far. It would be nice to hear from other platform. Especially Windows. Where someone needs to create a new build system. Sorry. Maybe that makes more sense to do when this code has landed in Apache subversion? 


## Command Line Use

The command line utility ```a2md``` (name preliminary), offers usage information when you start it:

```
usage: a2md [options] cmd [cmd options] [args]
	Show and manipulate Apache Manged Domains
  with the following options:
  -a | --acme    arg	the url of the ACME server directory
  -d | --dir    arg	directory for file data
  -h | --help    	print usage information
  -j | --json    	produce json output
  -q | --quiet    	produce less output
  -t | --terms    arg	you agree to the terms of services (url)
  -v | --verbose    	produce more output
  -V | --version    	print version
  using one of the following commands:
  	acme cmd [opts] [args]
  		play with the ACME server
  	add [opts] domain [domain...]
  		Adds a new mananged domain. Must not overlap with existing domains.
  	update name [ 'aspect' args ]
  		update a managed domain's properties, where 'aspect' 
  		is one of: 'domains', 'ca', 'account', 'contacts' or 'agreement'
  	drive [md...]
  		drive all or the mentioned managed domains toward completeness
  	list
  		list all managed domains
  	store cmd [opts] [args]
  		manipulate the MD store
```
Some of these options are more useful in testing. We leave them in for your curiosity, but please make a backup copy of your files before you experiment with them.

The most useful one to a server administrator are probably ```list``` to see the current status of all managed domains and ```drive``` with which you can signup/renew certificates from outside the server.

For example, if you have a cluster setup, ```auto``` drive mode is not for you, as each cluster node would try to get its own certificate. Probably better to use ```a2md``` and copy the files regularly to other nodes.


## Licensing

Please see the file called LICENSE.


## Credits

This work is supported by an Award from MOSS, the Mozillla Open Source Support project. Many thanks to these excellent people! You are awesome!

Test cases mostly written by my colleague @michael-koeller who made this to a good part really a test driven development. Thanks!

Münster, 22.07.2017

Stefan Eissing, greenbytes GmbH

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind. See LICENSE for details.


