
# mod_md - ACME for Apache

This repository contains `mod_md`, a module for Apache httpd that helps you to manage your domains.

## What is it good for?

`mod_md` does two things:

1. Provide ***SSL certificates*** for your domains from Let's Encrypt (or another Certificate Authority that supports the ACME protocol, rfc8555)
2. Offer robust ***OCSP Stapling*** of SSL certificates which is important for fast page loads in modern browsers.

Both functions work well together, but you can use one without the other. If you do not want the ACME/Let's Encrypt parts, there is ["Just the Stapling, Mam!"](#just-the-stapling-mam)

## Thanks

The following people directly contributed to `mod_md`:
Alvaro Octal, Andreas Ulm, Bernard Spil, Daniel Caminada, Dominik Stillhard,
  Fraser Tweedale, Giovanni Bechis, Jacob Hoffman-Andrews, Joe Orton,
  Josh Soref, Lubos Uhliarik, Max-Milan Stoyanov, Michael Kaufmann,
  Michael Köller, Michal Karm Babacek, Mina Galić, Moritz Schlarb,
  Stefan Eissing, Timothe Litt, @frasertweedale. 

Many thanks!

## Versions and Releases

This README always describes the current version of the module. This might not actually be what you use. You can look
into your Apache server log where `mod_md` logs its version at startup. 

 * `v2.4.x` releases are ***stable***. They can be used in production and new versions will be backward 
   compatible with existing configurations.
   Among other improvements v2.4.0 brings support for multiple certificates with different key types.
   The large feature added in v2.2.0 is OCSP stapling. This release line shipped in Apache httpd 2.4.46.
   Apache releases will always get the latest, stable version from here. 
 * The current releases require Apache httpd >= 2.4.48 

## Index

  - [HowTos](#howtos):
    * [Add a new `https:` Host](#how-to-add-a-new-host)
    * [Add `https:` to a `http:` Host](#how-to-add-https-to-a-host)
    * [Migrate an existing `https:` Host](#how-to-migrate-a-https-host)
    * [Have many Names for a Host](#how-to-have-many-names-for-a-host)
    * [Live with `http:`](#how-to-live-with-http)
    * [Live without `http:`](#how-to-live-without-http)
    * [Manage Server Reloads](#how-to-manage-server-reloads)
    * [Analyze and fix problems](#how-to-fix-problems)
    * [Platorm Specifics](#platform-specifics)
  - Advanced:
    * [Have one cert for several Hosts](#how-to-have-one-cert-for-several-hosts)
    * [Have an Extra Name in a Certificate](#how-to-have-an-extra-name-in-a-cert)
    * [Have Individual Settings](#how-to-have-individual-settings)
    * [Backup, Restore or Start Over](#how-to-backup-restore-or-start-over)
    * [Get a Wildcard Cert](#how-to-get-a-wildcard-cert)
    * [Use Other Certificates](#how-to-use-other-certificates)
    * [Have two certs for one Host](#how-to-have-two-certs-for-one-host)
    * [Use tailscale certificates](#tailscale)
    * [Have a failover ACME CA](#acme-failover)
    * [Revocations](#revocations)
    * [Use ACME Profiles](#profiles)
  - Stapling
    * [Staple all my certificates](#how-to-staple-all-my-certificates)
    * [Staple some of my certificates](#how-to-staple-some-of-my-certificates)
    * [Know which Stapling You Want](#how-to-know-which-stapling-you-want)

  - [Installation](#installation)
  - [Upgrading](#upgrading)
  - [Lets Encrypt Migration](#lets-encrypt-migration)
  - [Monitoring](#monitoring)
  - [Using Lets Encrypt](#using-lets-encrypt)
  - [Basic Usage](#basic-usage)
  - [Changing Domains](#changing-domains)
  - [Redirecting to https](#redirecting-to-https)
  - [Ports Ports Ports](#ports-ports-ports)
  - [TLS ALPN Challenges](#tls-alpn-challenges)
  - [Wildcard Certificates](#wildcard-certificates)
  - [Dipping the Toe](#dipping-the-toe)
  - [File Storage](#file-storage)
  - [Configuration Directives](#directives)
  - [Test Suite](#test-suite)

 
 
# HowTos

This is a list of recipes on how you can use ACME in your Apache configuration. This assumes that you are somewhat familiar with Apache's configuration directives `Listen`, `VirtualHost`, `SSLEngine` and friends. It also assumes that your Apache is running, has the basic modules loaded. You can see a document in your browser (maybe only on `http:` for now).

### Prerequisites

Your Apache is working and listens on port 80. It runs on a machine you can connect to. You want it to serve `https:`. And it should be _real_ `https:` with a certificate from Let's Encrypt and it should show a green lock (or whatever is the fashion nowadays) in browsers. 

Well, there are some prerequisites for that:

 * Do you have a domain name that your server should respond to? Let's call this `mydomain.com` for simplicity from now on.
 * Can you open `http://mydomain.com/` in a browser and get something back from your server?
 * Can you also do that from the internet? (When in doubt, switch off WLAN on your phone and open the browser from there)

This sounds good. You have a running setup for `http:`. In case you're not aware, `http:` runs on port 80. Somewhere in your Apache configuration there is a line like

```
Listen 80
```
`https:` listens on port 443. So, either this is already the case, or you need to add another `Listen` line for this. If you cannot immediately find it: some installations have it in another file that gets included. If it is not there, add it.

To use `mod_md` you need it loaded into your server. This varies a bit, depending on what installation you use. In debian/ubuntu, for example, there is a command to activate it:

```
> a2enmod md
Enabling module md.
To activate the new configuration, you need to run:
  service apache2 restart
```
There is no harm in doing this again:

```
> a2enmod md
Module md already enabled
```
Also make sure that `mod_ssl` and `mod_watchdog` are enabled. watchdog is often directly part of the server and not an external module. Then there is no need to enable it.

One more thing. There is usually an email address in your Apache configuration, configured with the `ServerAdmin` directive. Sometimes, it has a meaningless default. It has been mainly used in error responses as "Contact admin@something.com..." so far and people do not really lose sleep about it being an invalid address. Not so any more!

`mod_md` will use that email address when registering your domains at Let's Encrypt. And they will try to contact you with important news, should the need arise. So, make sure this is a real address that you monitor! 

If you want to be registered and contacted different email address, specify it with the MDContactEmail directive, which is preferred.

As the last thing, add the following line somewhere in your configuration:

```
MDCertificateAgreement accepted
```
With this you state that you accept the [Terms of Service](https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf) by Let's Encrypt.


## How to Add a New Host

Scenario: you have checked the [prerequisites](#prerequisites) and would like to add a new host that should be reachable via `https:`. 

As in all How To chapters, we use `mydomain.com` as the domain name. Exchange this with the name you actually have. In the Apache config (or one file included from it), you add now:

```
MDomain mydomain.com

<VirtualHost *:443>
  ServerName mydomain.com
  SSLEngine on
  DocumentRoot ...path-you-serve-here...
  ...
</VirtualHost>
```
and then you restart your server.

What did we do here? We made a host that answers on port 443 and we told `mod_ssl` that it should be active here. But we did not specify any certificates! If you look at examples for ssl in Apache on the web, there are always `SSLCertificateFile` and `SSLCertificateKEyFile` used. This is no longer necessary.

And while we left out parts of the SSL configurations that used to be necessary, we added one line of `mod_md` configuration: `MDomain <name>`. This is how you declare that a domain should be manged by `mod_md`. 

The module will use this name to find all hosts that belong to it and take care of those. When `mod_ssl` does not find any certificates, because you did not configure any, it will ask `mod_md`: "Hey, do you know anything about `mydomain.com`?" And it will answer: "Sure, use these files here for the certificates!"

During start up, the module will see that there are no certificates yet for `mydomain.com`. It could contact Let's Encrypt right away and request one - but who knows how long that might take. In the meantime, your server will not become active and request will just time out. No good. Instead it creates a temporary certificate itself for `mydomain.com` and pass that on to `mod_ssl`. Everything starts up and your server is responsive.

Now, when you open `https://mydomain.com/` in your browser now, it will complain because this temporary certificate cannot be trusted. If you tell it to ignore these security considerations (well, you should not), your server will answer every request to mydomain.com with a "503 Service Unavailable" message.

In the meantime, right after the Apache has started, `mod_md` will contact Let's Encrypt and request a certificate for your. This usually takes less than a minute. There are several ways to check the progress of this ([see Monitoring](#monitoring) for more), but for this first time you should maybe look into the server's error log.

If you find an entry there like:

```
[Date] [md:notice] [pid nnn] AH10059: The Managed Domain mydomain.com has been setup 
and changes will be activated on next (graceful) server restart.
```

If this does not happen, something is not right and [you should read here on how to analyze and fix problems](#how-to-fix-problems). But assuming this worked, you now simply do a reload of the server and `https://mydomain.com/` should work nicely and with a green lock in your browser. ("reload" is just a short name for a "graceful" restart, one that does not interrupt ongoing requests.)

Congratulations!

## How to Add https to a Host

Scenario: you have a Host responding to `http:` requests, you have checked the [prerequisites](#prerequisites) and would like to have that host reachable via `https:` as well.

As in all How To chapters, we use `mydomain.com` as the domain name. Exchange this with the name you actually have. In the Apache config you will have something like this already:

```
<VirtualHost *:80>
  ServerName mydomain.com
  DocumentRoot ...path-you-serve-here...
  ...
</VirtualHost>
```

This is the host that you already have. Now, make a copy of that, change the port and switch SSL on:

```
MDomain mydomain.com

<VirtualHost *:80>
  ServerName mydomain.com
  DocumentRoot ...path-you-serve-here...
  ...
</VirtualHost>

<VirtualHost *:443>
  ServerName mydomain.com
  SSLEngine on
  DocumentRoot ...path-you-serve-here...
  ...
</VirtualHost>
```

Then you reload your Apache server. It will start up right away, as before, and your `http://mydomain.com/` links will work as they used to. If you open `https://mydomain.com/` in your browser, you will get a security warning. If you tell it to ignore that you will get a `503 Service Unavailable` response.

What is happening? At start up, mod_md generated a self-signed certificate for the new https host to use and switch that host to 503 responses. This made sure that your server started without delay and that your other hosts could start working.

When Apache is done with start up, `mod_md` spins up a background thread that contacts LetsEncrypt and negotiates a certificate for `mydomain.com`. This usually takes a few seconds, but there are several things that may delay this: bad internet connectivity, maintenance at LetsEncrypt, problems with DNS resolutions somewhere, etc.

There are several ways to check the progress of this ([see Monitoring](#monitoring) for more), but for this first time you should maybe look into the server's error log.

If you find an entry there like:

```
[Date] [md:notice] [pid nnn] AH10059: The Managed Domain mydomain.com has been setup 
and changes will be activated on next (graceful) server restart.
```

If this does not happen, something is not right and [you should read here on how to analyze and fix problems](#how-to-fix-problems). But assuming this worked, you now simply do a reload of the server and `https://mydomain.com/` should work nicely and with a green lock in your browser. ("reload" is just a short name for a "graceful" restart, one that does not interrupt ongoing requests.)


## How to Migrate a https: Host

Scenario: you have a Host responding to `https:` requests already that has valid certificates. You want this host to be managed by `mod_md` with certificates from LetsEncrypt. You have checked the [prerequisites](#prerequisites).

As in all How To chapters, we use `mydomain.com` as the domain name. Exchange this with the name you actually have. In the Apache config you will have something like this already:

```
<VirtualHost *:443>
  ServerName mydomain.com
  SSLEngine on
  SSLCertificateFile /etc/mycertificates/mydomain-certs.pem
  SSLCertificateKeyFile /etc/mycertificates/mydomain-key.pem
  DocumentRoot ...path-you-serve-here...
  ...
</VirtualHost>
```

You add one line to this, maybe just before the `VirtualHost`:

```
MDomain mydomain.com

<VirtualHost *:443>
  ServerName mydomain.com
  SSLEngine on
  SSLCertificateFile /etc/mycertificates/mydomain-certs.pem
  SSLCertificateKeyFile /etc/mycertificates/mydomain-key.pem
  DocumentRoot ...path-you-serve-here...
  ...
</VirtualHost>
```
and reload you Apache server. Your server will start up as before and `https://mydomain.com` will also work as before. If you look at the certificate in your browser, it will be the same as before - namely the one from `/etc/mycertificates/mydomain-certs.pem`.

In your error log, you will however find a new entry:

```
[Date] [ssl:warn] [pid nnn] Init: (mydomain.com) You configured certificate/key files on this host, but 
it is covered by a Managed Domain. You need to remove these directives for the Managed Domain to take over.
```

In the meantime, `mod_md` is negotiating with LetsEncrypt for a new certificate for `mydomain.com`. There are several ways to check the progress of this ([see Monitoring](#monitoring) for more), but for this first time you should maybe look into the server's error log. If you find an entry there like:

```
[Date] [md:notice] [pid nnn] AH10059: The Managed Domain mydomain.com has been setup 
and changes will be activated on next (graceful) server restart.
```

(If this does not happen, something is not right and [you should read here on how to analyze and fix problems](#how-to-fix-problems).)

Now remove `SSLCertificateFile` and `SSLCertificateKeyFile` from your host. It should look now like this:

```
MDomain mydomain.com

<VirtualHost *:443>
  ServerName mydomain.com
  SSLEngine on
  DocumentRoot ...path-you-serve-here...
  ...
</VirtualHost>
```

Reload you Apache. Open `https://mydomain.com` in your browser. It should have a green lock and a certificate from Lets Encrypt now.

## How to Have many Names for a Host

In all examples so far, we used just `ServerName` in every `VirtualHost`. Our Managed Domains just had a single name.

It is very common to have more than one name and use `ServerAlias` to add them. A more typical host looks like this:

```
MDomain mydomain.com

<VirtualHost *:443>
  ServerName mydomain.com
  ServerAlias www.mydomain.com
  ...
</VirtualHost>
```

`mod_md` automatically looks at all domain names in hosts. You do not have to specify that. It will see `www.mydomain.com` and get a certificate that covers both names. It also works the other way around:

```
MDomain mydomain.com

<VirtualHost *:443>
  ServerName www.mydomain.com
  ServerAlias mydomain.com
  ...
</VirtualHost>
```

In general, it is good practise to use the shorter name in `MDomain`. It does not matter if that appears in `ServerName` or `ServerAlias`.

This check is done every time you start or reload Apache. If you add a name to your host, as in:

```
MDomain mydomain.com

<VirtualHost *:443>
  ServerName www.mydomain.com
  ServerAlias mydomain.com
  ServerAlias forum.mydomain.com
  ...
</VirtualHost>
```

`mod_md` will detect that the existing certificate does not cover `forum.mydomain.com` and contact LetsEncrypt to get a new one.

Should you _remove_ a name from a host, it will also see that. But since the existing certificate is still valid for all the names that are there, it will not renew the certificate. But when renewal is due anyway, it will use the new, shorter list of names.

One more advice: if you remove the name that you use in `MDomain` from a host, the host is no longer found. While there are ways to tricks around this, it is not recommended to go that direction. That is why using the shortest name is best in most cases.


## How to Live with http:

If you start a new domain nowadays, you probably only make it available via `https:`. But if you have been around for longer, your `http:` links maybe in use by many sites and you want to continue supporting those. However, since `http:` answers are being monitored and tampered with, you most likely want to redirect those to you `https:` equivalents.

There is, for example, `mod_rewrite`, which you can use for this. But `mod_md` also offers a directive:

```
MDRequireHttps temporary
```

which answers `http:` requests to a Managed Domain with a `302 Temporary Redirect` to the `https:` one (same path and query). 

The code 302 means that clients should continue asking for the original `http:` resource. So, should you change your mind, no harm is done. But if it all works out, your server should send clients a `301 Redirect` which instruct clients to always use the `https:` link and forget the other. As you might have guessed, you do this with:

```
MDRequireHttps permanent
```

This setting has another side effect: responses to `https:` requests are also marked as `permanent`. This uses the HTTP header [`Strict-Transport-Security`](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) to let clients know that they should never (e.g. for the next 6 months) talk http: to this domain. If they see a http: link, they will convert that to https: right away.


## How to Live without http:

In the previous howto, the support for `http:` links was addressed. Important for people who want to migrated existing sites to https:. But not having `http:` at all poses its own challenges. This happens, for example, when providers switch port 80 off for security reasons.

When your server negotiates a certificate with Let's Encrypt, this can be done in 3 different ways:

 1. using the `http:` protocol (port 80)
 2. using the `tls` protocol with `ALPN` (the `s` part of `https:`) (port 443)
 3. using the `DNS`

This is true for _all_ Let's Encrypt clients: `certbot`, `acme.sh`, `mod_md`, etc.

Assuming you do not have a DNS setup working, and your port 80 is blocked, this leaves only port 443. Let's Encrypt will open a connection to your server on this port and indicate that it wants to talk a very specific protocol named `acme-tls/1`. It then expects a very specific answer from the server.

For this to work with your Apache, you need to enable this protocol using the `Protocols` directive. See [TLS ALPN Challenges](#tls-alpn-challenges) for details.


## How to Manage Server Reloads

When Apache ACME gets a new certificate they do not automatically become active. You need to *reload* the
server. The common command `apachectl` calls this `graceful`. `systemd` calls it `reload`. 

However you call it, a full restart is not necessary. This is less disruptive, since a reload will finish ongoing
requests.

When you get your first certificates via Apache ACME, you will probably monitor this closely and do the reloads
yourself. But after that, you probably want this automated. There are several options.

You can add the reload command to root's crontab (or whichever user starts your apache). Depending on the 
platform you use, this may be done via `systemd` or `apachectl`. To be safe, run this daily when you have
a time of day with low traffic. A weekly reload would probably also suffice, since ACME certificates are
commonly renewed early enough.

You can use [MDMessageCmd](#mdmessagecmd) to add a script to run when certificates are renewed. While this
command has probably not the privileges to restart your apache, it may send you an email about it. You can
also do some `sudo` magic to give it allowance for reloads. But be aware that these also may happen during
busy hours.

Another thing you can do is combine those. Make a [MDMessageCmd](#mdmessagecmd) that creates a file, like `/tmp/apache-reload-required` and a cronjob that checks the presence of it, makes a reload and removes that file again.

It's really up to your system and traffic what is best here. For most sites, which have times of day with little traffic, I recommend the simple approach with a daily reload via crontab.


## How to Fix Problems

The feedback from people using `mod_md` has been very positive, especially about the simplicity of the configuration. (However some people do not like this and seem to prefer more explicit configs. You can't please everyone.) Some people run into problems. Maybe there is a bug in `mod_md`. Maybe they have a networking setup that requires some special configurations, because the defaults just do not suffice.

And then there are, of course, things that break. E.g. your internet becoming partially unavailable. Google/AWS outages, etc. 

In the presence of always-possible, temporary disasters, auto-renewing your server certificates _in time_ is helpful. `mod_md` will renew certificates when a third of their lifetime is left. Since Let's Encrypt issues certificates valid for 90 days, such certificates are renewed 30 days in advance.

Besides the Apache error logs, where 'mod_md' also logs problems, there are two ways to monitor your Managed Domains: `server-status` and `md-status`. See [the chapter about Monitoring](#monitoring) for more details.

The best place on the net to check/discuss problems with Let's Encrypt is [community.letsencrypt.org](https://community.letsencrypt.org). Very helpful.

### Outgoing

Your Apache server reports that it has problems contacting Let's Encrypt. The problems can be

 * unable to connect: you should check if Let's Encrypt is reachable at all for you. The default `MDCertificateAuthority` is [https://acme-v02.api.letsencrypt.org/directory](https://acme-v02.api.letsencrypt.org/directory) and you should check if it answers. If it does, check if it answers also on the machine that your Apache runs on. Some server installations block outgoing connections. Maybe your server needs to use a HTTP proxy? See [MDHttpProxy](#mdhttpproxy) in that case.
 * unexpected status: `mod_md` got a response, but with an unexpected status code. For example:
   * `503`: this would indicate that Let's Encrypt does maintenance on their servers. This should go away after a short while.
   * other `5xx`: category _should not happen_. This points to an error in the LE software. Check the community.
   * `4xx` codes: LE thinks that `mod_md` has sent an invalid request. Check the current `mod_md` github for fixes. Check the community, if the issue is known. Or open a new issue at the github repository.
 * failure to parse the response: the only known case of this is when people configured their own `MDCertificateAuthority` and entered a wrong URL.
 * error in parsed response: in some cases, Lets Encrypt answers with an error document. This describes what went wrong from its perspective. For example, it could answer that it was unable to contact your server. Have a closer look at the description. Maybe something is wrong with your _incoming_ setup.

### Incoming

There are different areas where problems with _incoming_ connections to your Apache can appear:

  1. `mod_md` does not understand your network setup and complains. A common cause is that your server is behind a port mapper (internet modem, firewall) and does not listen to ports 80 and 443. Instead, it listens to - for example - 8000 and 8001. Use the directive [MDPortMap](#mdportmap) to tell the module where http/https request will arrive.
  1. `mod_md` _thinks_ it understands your network, but reality is far from it. For example, your Apache listens on port 80, but this port is not reachable from the internet. Maybe you use it just locally. `mod_md` might tell Let's Encrypt to use port 80, but that will then never succeed. In this case, configure `MDPortMap 80:-` to disable it for mod_md.
  2. Let's Encrypt is unable to reach your server, using one of the Managed domain names. You must understand that if your host has a variety of names (using `ServerAlias`), Let's Encrypt will need to verify _all of them_. If you use aliases that only resolve in your local network, you need to split your `VirtualHost` for that. In doubt, check that all domains of yours will reach your server - from the internet. Maybe a DNS record has the wrong address?
  
### Challenges

Sometimes, `mod_md` will not be able to get/renew a certificate because it cannot detect a suitable challenge method for LetsEncrypt. 

The most common cause is that you request a wildcard certificate, e.g. `*.mydomain.com` but do not have `MDChallengeDns01` configured. Let's Encrypt offers only DNS challenges for wildcard certificate. There is no choice. If your server is not able/configured to answer those, it will not work.

Another cause: if your server is not reachable on port 80 and you have not configured `acme-tls/1` (see [TLS ALPN Challenges](#tls-alpn-challenges) for details). Again, mod_md is not able to select a challenge for Let's Encrypt to perform.

Read the [chapter about ports](#ports-ports-ports) for more information about what is going on and what you can do.

## Platform Specifics

The module is used on various platforms. Some require special attention:

### CentOS 8 advice by @marcstern 

The chrooted `md` directory [where are certificates are stored] must be have the following properties:

```
owner: root -> rwx
group: apache (or www-data or equivalent) -> rwx
```

Under Redhat (tested on 8), the normal & chrooted "md" directories must be have the following SELinux context:

`system_u:object_r:httpd_var_lib_t:s0`

For a discussion of the problems @marcstern encountered, see also issue #253.


# Advanced HowTos

## How to Have one Cert for Several Hosts

A feature we did not cover so far: you can specify more than one name in `MDomain`:

```
MDomain mydomain.com another.org

<VirtualHost *:443>
  ServerName mydomain.com
  ...
</VirtualHost>

<VirtualHost *:443>
  ServerName another.org
  ServerAlias www.another.org
  ...
</VirtualHost>
```

This will treat both hosts as belonging to the same Managed Domain. One certificate will be requested from Let's Encrypt and that will cover both names and all connected aliases. 

It depends on the domains and their use if this is a good approach or not. It might help browsers in using the same connection for both (browsers have sophisticated evaluation methods for this, it might not be as straightforward as your think). On the other hand, the more names in your certificate, the larger it is. Since it is sent to clients on every connection, there is overhead.

But, if it makes sense in your setup, this is how you do it with `mod_md`.

## How to Have an Extra Name in a Cert

Certificates are not only used in web servers like Apache. Mail and IMAP servers also make good use of them. Let's Encrypt can make those too, with a little bit of additional config.

If you want a certificate for `mail.mydomain.com` you need to make sure that `http:` and/or `https:` requests for that domain _from the internet_ arrive at your Apache. Maybe, you have a small setup where everything is on the same machine anyway, then there is nothing more to do. Should it be on another ip address, maybe port forwarding can help.

Let's say, you have solved this. You then configure:

```
MDomain mydomain.com mail.mydomain.com

<VirtualHost *:443>
  ServerName mydomain.com
  ...
</VirtualHost>
```

The mail domain gets added to the Managed Domain, but it does not need to appear in any host. `mod_md` will get a certificate that covers both names.

Should you want a _separate_ certificate for it, you can make a new MDomain, like:

```
MDomain mydomain.com
MDomain mail.mydomain.com

<VirtualHost *:443>
  ServerName mydomain.com
  ...
</VirtualHost>
```

Apache will accept this configuration, but - as you will find out - will not request a certificate for the mail domain. What is happening?

`mod_md` sees that `mail.mydomain.com` is not used in any host. Therefore, there is no need to have a certificate for it. This is what the module calls the `MDRenewMode` and it is `auto` by default. If you change this to `always`, it will request certificates also for managed domain that appear not to be in use.

## How to Have Individual Settings

If you have more than one Managed Domain, you soon run into the situation where you want different settings for them. You can use `<MDomain >` to achieve this:

```
MDomain mydomain.com

<MDomain another.org>
  MDRequireHttps permanent
</MDomain>

<VirtualHost *:443>
  ServerName mydomain.com
  ...
</VirtualHost>

<VirtualHost *:443>
  ServerName another.org
  ...
</VirtualHost>
```
This will switch on the permanent redirect to `https:` for `another.org` only. You can use this for most configuration directives of `mod_md`: authority url, drive mode, private keys, renew window and challenges.

## How to Backup, Restore or Start Over

`mod_md` stores all data as files underneath the `md` directory - or where ever you configured `MDStoreDir` to be. See [File Storage](#file-storage) for a description of this. If you backup this directory, you will have a copy of all your certificate and keys.

While this is nice, it is worth remembering that the master data is your Apache configuration. The rest is just created by it. This means, if you _only_ restore this `md` directory and _not_ the Apache configuration files, this will be pretty meaningless.

On the other hand, if you restore the configuration and _not_ the `md` directory, your Apache will request all necessary certificates anew and, after a short while, you will be back to where you started. With different, but valid certificates nevertheless.

Therefore, in case of severe troubles, it is an option to throw away the `md` directory and make a restart (if you can live with the interruption of service, of course). You can also delete individual sub directories or even files, if you think there are problems lurking.

One thing to keep in mind, though, is that Let's Encrypt has a rate limit of 50 certificates per domain per week. If you do this too often, it may block requests for a while. But should you wish to experiment freely, try the _staging environment_ as described in "[Dipping the Toe](#dipping-the-toe)".

## How to Get a Wildcard Cert

A wildcard certificate is one like `*.mydomain.com` which is valid for all sub domain of `mydomain.com`. Let's Encrypt has special requirements for those and you need to do some extra lifting to make them work. See the chapter about [`MDChallengeDns01`](#mdchallengedns01) for a description.

But do you need a wildcard certificate? Some common reasons are:

 * Your Apache is a reverse proxy for a large number of domains. It terminates the TLS and forwards all requests to a backend, using a single configuration host.
 * You need a certificate for a lot of domains, but it should be nevertheless small in size. A too large certificate may increase load times for your pages.
 * You want to make it easy for a browser to reuse the same connection for other domains too. Maybe many domain pages have links to other sub domains and this speeds up loading.
 * You have many hosts in your Apache and have used one wildcard certificate in the past, because it was the cheapest option with the least hassle. 

It may now be less hassle to have individual Managed Domains with individual certificates. After all, `mod_md` gets them for you and watches expiry times, etc. But there are still good reasons for wildcards. Just consider it from the new, automated angle.

# How to Use Other Certificates

Since version v2.0.4 you can define Managed Domains for certificates that come from somewhere else. Before, you either configured `mod_ssl` or you had Let's Encrypt certificates via `mod_md`. Now you can mix. If you have a configuration like:

```
<VirtualHost *:443>
  ServerName mydomain.com
  SSLCertificateFile /etc/ssl/my.cert
  SSLCertificateKeyFile /etc/ssl/my.key
  ...
</VirtualHost>

<VirtualHost *:443>
  ServerName another.org
  SSLCertificateFile /etc/ssl/my.cert
  SSLCertificateKeyFile /etc/ssl/my.key
  ...
</VirtualHost>
```

You can change that to:

```
<MDomain mydomain.com another.org>
  MDCertificateFile /etc/ssl/my.cert
  MDCertificateKeyFile /etc/ssl/my.key
</MDomain>

<VirtualHost *:443>
  ServerName mydomain.com
  ...
</VirtualHost>

<VirtualHost *:443>
  ServerName another.org
  ...
</VirtualHost>
```
This not only saves you some copy&paste. It also makes all other features of `mod_md` available for these hosts. You can see it in `server-status` and `md_status`. You can manage redirects with `MDRequireHttps`. You can let them take part in the upcoming OCSP Stapling implementation.

Such a domain will not be renewed by `mod_md` - unless you configure `MDRenewMode always` for it. But even then, the files you configured will be used as long as you do not remove them from the configuration.

## How to Have Two Certs for One Host

A feature new since version 2.4.0 is that you can have more than one certificate for a domain. Just
configure more than one private key:

```
<MDomain mydomain.com>
  MDPrivateKeys secp256r1 rsa3072
</MDomain>
```

Such a configuration will obtain 2 certificates from your ACME CA (e.g. Let's Encrypt). Both
will be added to your `https:` hosts and the SSL library will choose the one best matching a
connecting client. Search the internet for `ECDSA` if you want to learn more about this kind of 
cryptography, its advantages and restrictions.

The name `secp256r1` stands for a specific variant in this ECDSA. `mod_md` places no
restriction on the names here, it passed them on to the SSL library which either knows them
or not. If you specify an unsupported key type, the renewal of certificates will fail with the
message that the type is unsupported.

Besides support in the SSL library, it is also important to note that the Certificate Authority,
i.e. Let's Encrypt, also needs to support it. A good example is `secp192r1` which OpenSSL knows
but Let's Encrypt rejects.

To make it all the more confusing, there are possibilities to parameterize these curves, but this
is left to `mod_ssl` and whatever configuration capabilities the SSL library has.

The certificates will be listed individually in the JSON data from `md-status`. The httpd `server-status`
will show aggregated information regarding valid and renewal times.

The renewal is triggered by the certificate that expires first. The renewal process will renew
all certificates. For Let's Encrypt, this does not make a difference, since lifetimes for RSA and
ECDSA certificates are handled the same. It is expected that other CA will do the same.


# A key to bind them

Several CAs now support the ACME protocol that manage customers accounts and need to tie ACME
clients to those accounts. This allows them to tie ACME certificates into their web interfaces,
for example. Or impose limits based on the subscription type.

The ACME standard (rfc8555) defines a feature called "External Account Binding". An ACME client
is provided with a Key Identifier (key-id) and a number of bits, base64 encoded, (hmac) that
gets used on registration at the ACME server. The client sends the `key-id` and "signs" the
registration with the bits, allowing the ACME CA to connect this registration to one of its
known accounts.

If you use such a CA and do not configure an EAB, the registration fails and you will see the
appropriate error code in the MDomains job log (common error: `externalAccountRequired`). If
you configure an unknown/wrong EAB value, the registration will also fail and you'll most
like see the error `unauthorized`.

Where you get the EAB values is a matter of the CA. Most have a web interface where you login
and can create EAB values that tie to your account. Since these would be usable by anyone, you
should keep those value to yourself. 

In Apache, you then add the following to your configuration (example from the test suite):

```
MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W
```

If you do this globally, it applies to all your managed domains. To have it only for a
particular domain, use something like:

```
<MDomain mydomain.com>
  MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W
</Mdomain>
```
just as you can do with other configurations of `mod_md`.

If you have done this for a domain and gotten a new certificate, Apache will have registered
an local 'ACME account' and placed this in the md store under `md/accounts/ACME-*/account.json`.
All information is kept there. For example like this (again, from the test suite):

```
{
  "status": "valid",
  "url": "https://localhost:14000/my-account/8",
  "ca-url": "https://localhost:14000/dir",
  "contact": [
    "mailto:admin@mydomain.com"
  ],
  "orders": "https://localhost:14000/list-orderz/8",
  "eab": {
    "kid": "kid-1",
    "hmac": "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
  }
}
```

If you change the EAB afterwards, nothing will happen until the certificate needs to be renewed. Then
Apache will find the EAB changed and, having no account with that EAB, will register anew at
the CA.

Should you change back to the old EAB value, a renewal will find the previous account in `md/accounts/ACME-*`
and use that one. No new registration will be done.

It depends on the CA, if there are any limits on EAB values and ACME accounts connected via them. Since it
needs to track those, they will not come without restrictions. But several EAB values active at the
same time seems common practise.


# Tailscale

**Update**: this section is **historical** now. Tailscale have changed the API for certificate retrieval
and this setup is no longer working. If someone with time and knowledge can make that working, I'd be 
more than happy to accept a PR.

The secure networking provided by [tailscale](https://tailscale.com) allows you to connect your own devices
in a very easy way without fiddling with firewalls and without public IP addresses. It's a bit of magic.

In its recent versions, it can also give you domain names and your own subdomain underneath the `*.ts.net` suffix. Something like `*.headless-chicken.ts.net` can be yours and your machines appear as, for example, `my-raspberry.headless-chicken.ts.net` in your own network.

But if you run a webserver on it, you'd need a certificate that your browser accept. And tailscale also does 
that magic and negotiates with Let's Encrypt to provide you with a valid one (and renews it).

Via `mod_md`, you can make use of that service (if you are on **linux** for now). To stick with the example above, you'd configure:

```
<MDomain my-raspberry.headless-chicken.ts.net>
  MDCertificateProtocol tailscale
  MDCertificateAuthority file://localhost/var/run/tailscale/tailscaled.sock
</MDomain>

<VirtualHost *:443>
  ServerName my-raspberry.headless-chicken.ts.net
  SSLEngine on
  ...
</VirtualHost>
```

If you do this on a distribution like `debian` your Apache runs as user `www-data` and you need to
tell the tailscale demon to give access to it. See [here for a description by tailscale on how to do this](https://tailscale.com/kb/1190/caddy-certificates/).

This then works just like certificates from Let's Encrypt. `mod_md` will give you status information on the cert
and also try to renew it and give you notifications via `MDMessageCmd`. OCSP stapling should be available as
well, but I have not tested that.

One thing to beware: Apache's attempts to renew, e.g. get a new certificate from the tailscale demon, are
not necessarily in sync. You might want to adjust your `MDRenewWindow` to only trigger right after tailscale
should have gotten a new one.

Also, for server restarts, the same rules apply as for ACME certificates.

Is there a dependency between the Apache service and your tailscale daemon? **No**. Both will
start and operate independent of each other. Apache will start also if your tailscale daemon is down. Just like your Apache will work when Let's Encrypt is not reachable for a while.

**Caveat**: if your Apache is *also* reachable from the public internet, the tailscale domain name will not
give you enhanced security. Anyone who can contact your server can ask for any domain in `*.ts.net`. There are
a myriad of options to make secure setups and you should consult the tailscale documentation on how/when/if
security in a tailscale network can be managed.

**Credits**: the nice and friendly [Caddy server](https://caddyserver.com) was the first HTTP server to add
tailscale support a couple of days ago. Which inspired me to strive for second place.

# ACME Failover

Since version 2.4.16, more than one ACME CA may be configured. An example would be:

```
MDCertificateAuthoriy letsencrypt buypass
```

which would use letsencrypt to obtain/renew certificates, just as before. But should Lets Encrypt
fail for a number of times, Apache will switch to buypass. Should buypass also fail these number
of times, letsencrypt is selected again. And so forth. You may configure even three or more CAs.

The directives `MDRetryDelay` and `MDRetryFailover` allow you to configure how fast the failover
happens. The default setting will do the failover after half a day of unfortunate events.

With the current 90 days lifetime of certificates, the reliability gains with more than one
CA are minor. Apache, by default, starts renewal 30 days before expiry, ample time to survive
any error downtime of a CA.

Shorter lifetimes however are desirable, since certificate revocation is not working very well. If certificates 
would only be viable for a couple of days, a revocation would no longer be necessary in most cases as
it cannot be done effectively before the certificate expires anyway.

The problem is that the duration of disasters are hard to shrink. With shorter lifetimes, the
probability rises that a CA is unavailable during the time of a renewal. An easy counter
is the configruation of a second CA as failover in the client, e.g. Apache.

# Revocations

The module does not provide for certificate revocations. If you need to revoke a certificate of yours, please 
contact your ACME provider for documentation on how to do that. Notice that your certificates can not only
be revoked by you. The ACME providers can also do that (and have done so in the past!).

If you enable OCSP Stapling (see below), your Apache will check the status of certificate regularly. This
way, it will learn when a certificate has been revoked. Since version 2.4.26 of the module, this will be
observed when checking certificates and cause a renewal.

You might want to consider choosing a shorter `MDCheckInterval`, if you need Apache to react more quickly to a
revocation. But keep in mind that your server needs a graceful restart for new certificates to activate. If you
restart only once every other day, shorter check intervals will not help.

It depends on your sites' specifics how fast you need Apache to react to revoked certificates. If about 6 hours would work for you, the following setting will do:

```
MDStapling on
MDStaplingRenewWindow 6h
MDCheckInterval 1h
```

`MDStaplingRenewWindow 6h` will get a new OCSP response for your certificates every 6 hours, ignoring the lifetime your CA sets. Once a CA publishes the revocation of your certificate, Apache will see it 6 hours later in the worst case, most likely sooner. Setting this shorter will result in more requests to your CA and they may not be happy about this if many people do it. OCSP requests are HTTP POST requests, so caching responses is not as cheap as with GET (no, I do not know why the OCSP inventors did this).

`MDCheckInterval 1h` makes your Apache check all Managed Domains every hour. If your certificates are valid and Stapling has not found any revocations, this is very cheap. It will then *not* results in any additional requests. It "wastes" only cpu time. If you have some spare, you may run this even more often without harm. This setting then gives an average 3 hours to detect a revocation and half an hour to react on it and start renewing the certificate. Tweak for your needs. 

**But remember**: the renewal puts a new cert into your file system. You need a server reload to make it active! Another choice for you to make. Small sites will have not trouble, but big installations may not want to do this during busy hours. If you do not want to reload during the day/week, small check/renew times will not help you.

In order to treat revocations special, you may consider monitoring the OCSP stapling by asking your Apache about it. You can use a special client that checks OCSP stapling (hint: `curl --cert-status` may do). Or you can use the module's `md-status` handler to retrieve a domain status in JSON from Apache.

# Profiles

[Lets Encrypt announced](https://letsencrypt.org/2025/01/09/acme-profiles/) they will add Certificate Profiles support
in their CA during 2025, beginning with their staging servers. This, among some other details, let's you select the lifetime
of the certificates you get. The "default" profile will keep the 90 days and a "tlsserver" profile will issue certificates with only 6 days of validity.

If you do not change your `mod_md` configuration, you will continue to get the 90 days certificates. Should you believe 
that a shorter lifetime is beneficial for you (and take the risk that the renewal time is way shorter), you can configure
the profile to use:

```
MDProfile tlsserver
```
You may set that for an individual MDomain as well. If the ACME CA supports that profile, `mod_md` will order the 
certificate with it. Should the ACME CA have no profiles, or non matching your configuration, `mod_md` will use
no profile. This was chosen as default behaviour to keep your certificate renewals going, even if the CA changes
its set of profiles.

If you really want to have only certificates of a given profile, you can make it mandatory:

```
MDProfile tlsserver
MDProfileMandatory on
```

and cert renewal will fail of the profile is not supported by the CA.

# Just the Stapling, Mam!

If you just want to use the new OCSP Stapling feature of the module, load it into your apache and configure

```
MDStapling on
MDStapleOthers on

<IfModule ssl_module>
  SSLUseStapling on
</IfModule>
```

and the module will provide the stapling for all your sites. If you use a module other than `mod_ssl` for your
https: sites, you may need to activate stapling for them as well.

You can see it [in your server status pages](#how-would-you-know-it-works) for which sites stapling information is delivered. 


# How to Staple All My Certificates

If you want to have Stapling for all your certificates in your Apache httpd, you have two options: either you use the `SSLStapling` provided by `mod_ssl` or the new one from `mod_md`. If you want to switch over to this implementation, you configure in your base server:

```
MDStapling on
```

and `mod_md` will manage all. This *overrides* any `SSLStapling` configuration. You can leave that on, but it will have no effect. 

This is a bit of a bold approach, however. A more controlled rollout might be better. Read the next chapter on the options.

# How to Staple Some of My Certificates

For this, it is useful to know about how TLS modules like `mod_ssl` and `mod_md` work together in the server.
When you configure:

```
SSLUseStaping on
```

`mod_ssl` will add stapling data to each new connection. It will ask around if someone in the server is
willing to provide it and, if none does, use its own stapling implementation. If you configure `SSLUseStapling off`, it
will never ask `mod_md` for the data.

If you want some of your sites stapled and some not, you would configure something like this:

```
<VirtualHost *:443>
  ServerName a.exampl.org
  SSLUseStapling on
</VirtualHost>

<VirtualHost *:443>
  ServerName b.exampl.org
  SSLUseStapling off
</VirtualHost>
```
Site `b` then does not send stapling data to clients. And no `mod_md` configuration will change that.

What you configure in `mod_md` are the sites that the module retrieves and updates OCSP information
for, *in case someone like mod_ssl asks for it*.

For example with:

```
<MDomain mydomain.net>
  MDStapling on
</MDomain>
```

OCSP data management will be enabled just for `mydomain.org`. For all other sites, `mod_ssl` will
continue to manage it.

# How Would You Know It Works?

If you have Apache's `server-status`handler enabled, you can open that page in your browser. With `MDStapling on`
there will be a new section, like:

![A server-status with mod_md stapling information](mod_md_ocsp_status.png)

Here you see all domains listed for which `MDStapling` is enabled. For most sites, there will be one certificate per domain, but it is possible to have more. Certificates are listed with their SHA1 fingerprint. The `Status` is the one reported by your Certificate Authority (the one listed under `Responder`). It is one of `good`, `revoked` or `unknown`.

`Valid` gives the times the *OCSP information*, not the certificate itself, are valid. If you hover, you get the exact timestamp. Before an OCSP answer times out, there will be an `Activity` to get an updated one. If something goes wrong, the last error encountered is also listed here.

All your certificates should have status `good`. If not, the `Check` link might help you further. It points to the page on `https://crt.sh` where that specific certificate is listed. This gives you a second opinion about your certificate. `crt.sh` is just on of the certificate monitors that are available. If you prefer using another, you can configure this via `MDCertificateMonitor` directive.

More detailed information about OCSP status/activities can also be retrieved from the `md-status` handler in JSON format (you need to enable that handler).

And last, but not least, a configured `MDMessageCmd` gets invoked whenever OCSP Stapling information is renewed or encounters errors. More in the description of that directive.


# How to Know which Stapling You Want

And why is Stapling important anyway? A short introduction might help:

### Stapling

When one of your certificates is compromised, you'd like to *revoke* it. The whole world should no 
longer trust it. So you tell your Certificate Authority (CA) which gave it to you in the first place: 
"Make it go away again!". Turns out, this is rather difficult for the CA.

When the internet was young and the number of certificates was small, CAs used to publish *Revocation Lists*
where all revoked certificates were listed. Clients were expected to download these lists regularly and no
longer trust certificates on the list. As you can imagine, these just grew too large and cumbersome
to use.

Then, online services were invented that allow a client to ask the CA: "Hey, I see this certificate of yours. Is it still good?". And this was much better as the question and the answer are quite short. This protocol is called OCSP and
it uses HTTP as transport. It has zero configuration since the URL to send the request to is part of the
certificate.

Since OCSP answers come with a valid lifetime, clients can cache them and do not have to ask the CA
*all the time*. But still, when a client connects to a site for the first time (or after a while when any OCSP response has timed out), it needs to contact the CA. Browsers did not like this very much. It delays loading of web pages (they want to be the fastest!) and maybe the CA is unreachable at that moment. How long should it wait?

The next innovation was then ***Stapling*** where the browser does not have to contact the CA. Instead, the
web server does it and sends the response to the client immediately on connect (well, during the SSL handshake). This
scales much better, browsers were happy. Only, servers now had one responsibility more to care about.

To keep SSL connects as fast as they used to be, servers need a valid OCSP response at the ready. Always. Because not
only browsers want to be fast, servers do care about that too! (I know, it's a shocker.)


### Stapling in mod_ssl

Apache's first stapling implementation was done in `mod_ssl`, naturally. The basic strategy is:

1. On a client connect, get the stapling response from the internal cache.
2. If it is not in the cache or no longer valid, retrieve a new response from the CA
3. Store the response in the cache and continue the connect.

This works. However, the first clients that connect will pay the penalty of waiting for
the cache update. Same for clients that connect on a stale response. Small price to pay, you
may think.

But *should the OCSP responder of the CA be down or unreachable* at that time, you will have a
long delay and eventually no response at all (there is a timeout). Which means that *all*
clients connecting to your site could experience this. And if clients take a missing response
as fatal, your whole site becomes unreachable (and they have to if you mark your certificates
with the `must-staple` extension).

On top of that, most examples of `mod_ssl` stapling configurations recommend a memory cache. This means that
all stapling responses are lost when you reload your server. Never reload when your CA is
down or unreachable? Hardly a manageable approach.


### Stapling in mod_md

Learning from this, the implementation in `mod_md` takes a different approach:

1. Start a task with `mod_watchdog` that monitors availability of Stapling data.
2. Retrieve missing data from the CA.
3. Also retrieve new responses before existing ones become invalid.
4. Store responses in the file system so they continue to be available after a server reload.

This prevents having client connections waiting. Either response data is there or not. Renewals
of the data are continuously happening in the background. They are attempted when less than
a third of the response lifetime are left (configurable). Let's Encrypt responses have a life time
of several days, for example. This gives more than a day to get a new one. 

Server reloads do not affect the state of this and can be done all the time.

That being said, it is a new implementation. There will be bugs lurking and it is probably
good advice to switch from the old stapling in a controlled way. Start with some domains
and see how it works for you.

### Why Both?

First, since Stapling has become a vital function of a web server in the modern times of `https:`, it is
a good idea to phase in something new and allow for a mixed configuration. 

Second, Apache has a strong focus on remaining backward compatible. Shipping a new stapling
in a 2.4.x versions forbids that we disrupt your working configurations.

And third, the new implementation has new dependencies. `mod_md` requires `mod_watchdog`
and `libcurl` and `libjansson`. Shipping a `mod_ssl` with those needs in a 2.4.x release
would certainly upset some people.


# Installation

This **mod_md requires Apache 2.4.41 or newer**.

### Build and install `mod_md`

Once Apache httpd is installed and runs, get a [mod_md release](https://github.com/icing/mod_md/releases) and configure it. You basically need to give it the path to the ```apxs``` executable from your apache built.

```
mod_md > ./configure --with-apxs=<where-ever>/bin/apxs --enable-werror
mod_md > make
mod_md > make install
```

Then you need to add in your ```httpd.conf``` (or other config file) the line that loads the module:

```
LoadModule md_module modules/mod_md.so
```
and restart ```httpd```.

## Windows

[@nono303](https://github.com/nono303) has builds available at his [github repository](https://github.com/nono303/mod_md).

You can also build your own mod_md on Windows. Requirements: APR/APR Util (as likely comes with your httpd distro), OpenSSL, Curl, Jansson, Apache HTTP Server, CMake installation, Visual Studio installation. The undermentioned example is intended for development and debugging. Production build should be done in the context of httpd build, exactly with the libraries your httpd uses.


```
mkdir build
cd build
vcvars64
cmake -G "NMake Makefiles"
 -DOPENSSL_ROOT_DIR=C:/Users/Administrator/source/openssl/target/
 -DCURL_LIBRARY=C:/Users/Administrator/source/curl-build/lib/libcurl_imp.lib
 -DCURL_INCLUDE_DIR=C:/Users/Administrator/source/curl-build/include
 -DAPACHE_ROOT_DIR=C:/Users/Administrator/source/Apache24/
 -DAPR_ROOT_DIR=C:/Users/Administrator/source/Apache24/
 -DAPRUTIL_ROOT_DIR=C:/Users/Administrator/source/Apache24/
 -DJANSSON_ROOT_DIR=C:/Users/Administrator/source/jansson/build
 -DCMAKE_BUILD_TYPE=Release ..

nmake

dir modules\
mod_md.exp  mod_md.lib  mod_md.so*  mod_md.so.manifest
```

## Debian

Debian unstable includes the latest Apache httpd release. If you want a newer version of `mod_md` on top of it, it should be easy to build it with the instructions above.

## Fedora

The module has become part of Fedora 31.

## Ubuntu

Version 2-x status: unknown, see #124.

### Version 1-x:

If you do not already build your Apache httdp yourself, you can get a prebuilt, current 2.4.x release via the  PPA by @oerdnj, see [here](https://launchpad.net/~ondrej/+archive/ubuntu/apache2/+packages). 

What you need to do to get the PPA installed is basically:

```
> sudo add-apt-repository ppa:ondrej/apache2                                                                                                                                                                                                     
> sudo apt update                                                                                                                                                                                                                                
> sudo apt install -y apache2 apache2-dev build-essential autoconf make libtool libssl-dev libjansson-dev libcurl4-openssl-dev
```

Then you get a [mod_md release](https://github.com/icing/mod_md/releases) and configure it:

```
mod_md > ./configure --with-apxs=/usr/bin/apxs --enable-werror
mod_md > make
mod_md > make install
```
Then you create two files in ```/etc/apache2/mods-available```

```
md.load:-----------------------------------------------
LoadModule md_module /usr/lib/apache2/modules/mod_md.so
-snip--------------------------------------------------

md.conf------------------------------------------------
LogLevel md:info
-snip--------------------------------------------------
```

enable the module and restart:

```
> sudo a2enmod md
> sudo service apache2 restart
```

## FreeBSD

The module is enabled in freebsd's apache24 package since August 2020 (thanks to Mina Galić, @igalic).


# Upgrading

Upgrading from `mod_md` v2.0.x to v2.2.x requires no action by you. The module will do any necessary data conversions and configuration settings have remaing compatible. Your domains should, after an upgrade, run as before without certificate being renewed - unless they are due for renewal anyway.

_Downgrading_ is ***not*** supported. There is not guarantee that you can go back without any problems. When in doubt, make a backup of your `mod_md` store in the file system before upgrading.

## Lets Encrypt Migration

Beginning of May 2019, Let's Encrypt [announced their end-of-life plans for ACMEv1](https://community.letsencrypt.org/t/end-of-life-plan-for-acmev1/88430). Please read this carefully if you use their certificates.

The gist is:
 1. End of 2019, they will no longer allow new accounts to be created on ACMEv1
 1. Summer 2020, they will no longer allow new domains to sign up.
 1. Beginning of 2021, they will disrupt the service periodically to wake up people dragging their feet.

What does that mean for users of `mod_md`?

First of all, if you are on version 1.x, you need to upgrade to v2.x of the module. ***No upgrade will overwrite any of your existing, explicit configurations.*** The key word here is ***explicit***: If you specify values in your configuration for `MDCertificateAuthority`, the module will use this as you wrote it.

If you have ***not*** configured this, version 2.x of `mod_md` will choose the ACMEv2 protocol with Let's Encrypt *for all upcoming renewals*! If you do not want this, you should configure `MDCertificateAuthority` yourself. You can now easily see, which configuration is used for your domains in the [new monitoring features](#monitoring).

(There was some back-and-forth about the question, if the module should do this automatic switch-over. People with special network setups can be hurt by this. Maybe their servers need special configurations to reach the ACMEv2 host of Let's Encrypt. But for the vast majority of people, this migration should just work. And many people will not read this documentation anyway and only start googling when things stopped working. Knowing that things will come to a stop in 2021, it seems better to start the migration with a high chance of success than suppressing it with a certainty of failure.)




# Monitoring

Apache has a standard module for monitoring [mod_status](https://httpd.apache.org/docs/2.4/mod/mod_status.html). With v2.x ```mod_md``` contributes a section and makes monitoring your domains easy. A snippet from my own server looks like this:

```
A typical server-status snipplet:
```

![A server-status with mod_md information](mod_md_status.png)

You see all your MDs listed alphabetically, the domain names they contain, an overall status, expiration times and specific settings. The settings show your selection of renewal times (or the default), the CA that is used, etc.

The ```Renewal``` column will show activity and error descriptions for certificate renewals. This should make
life easier for people to find out if everything is all right or what went wrong.

If there is an error with an MD it will be shown here as well. This let's you assess problems without digging through your server logs.

### In JSON

There is also a new `md-status` handler available to give you the information from `server-status` in JSON format. You configure it as

```
<Location "/md-status">
  SetHandler md-status
</Location>
```
on your server. As with `server-status` you will want to add authorization for this! 

If you just want to check the JSON status of one domain, append that to your status url:

```
> curl https://<yourhost>/md-status/another-domain.org
{
  "name": "another-domain.org",
  "domains": [
    "another-domain.org",
    "www.another-domain.org"
  ],
  ...
```

Since version 2.0.5, this JSON status also shows a log of activities when domains are renewed:

```
...
{
"when": "Wed, 19 Jun 2019 14:45:58 GMT",
"type": "progress", "detail": "The certificate for the managed domain has been renewed successfully and can be used. A graceful server restart now is recommended."
},{
"when": "Wed, 19 Jun 2019 14:45:58 GMT",
"type": "progress", "detail": "Retrieving certificate chain for test-901-003-1560955549.org"
},{
"when": "Wed, 19 Jun 2019 14:45:58 GMT",
"type": "progress", "detail": "Waiting for finalized order to become valid"
},{
"when": "Wed, 19 Jun 2019 14:45:50 GMT",
"type": "progress", "detail": "Submitting CSR to CA for test-901-003-1560955549.org"
},
...
```

You will also find this information in the file `job.json` in your staging and, when activated, domains directory. 

### certificate-status

There is an experimental handler added by mod_md that gives information about current and
upcoming certificates on a domain. You invoke it like this:

```
> curl https://eissing.org/.httpd/certificate-status
{
  "rsa": {
    "valid": {
      "from": "Mon, 01 Apr 2019 06:47:43 GMT",
      "until": "Sun, 30 Jun 2019 06:47:43 GMT"
  },
  "serial": "03D02EDA041CB95BF23B030C308FDE0B35B7",
  "sha256-fingerprint" : "xx:yy:zz:..."
  },
  "P-256": {
    ...
  }
}
```

This is information available to everyone already as part of your TLS connections, so this does
not leak. Also, it does not show which other domains are on the server. It just allows an easier,
scripted access.

When a new certificate has been obtained, but is not activated yet, this will show:

```
{
  "rsa": {
    "valid": {
      "from": "Mon, 01 Apr 2019 06:47:43 GMT",
      "until": "Sun, 30 Jun 2019 06:47:43 GMT"
  },
  "serial": "03D02EDA041CB95BF23B030C308FDE0B35B7",
  "sha256-fingerprint" : "xx:yy:zz:..."
  "renewal": {
	"name": "example.net",
        "finished": true,
        "notified": false,
        "last-run": "Thu, 02 May 2019 21:54:22 GMT",
        "errors": 0,
        "last": {
          "status": 0,
          "detail": "certificate status is GOOD, status valid Mon, 01 Apr 2019 06:47:43 GMT - Sun, 30 Jun 2019 06:47:43 GMT",
          "activity": "status of certid xxyyzzqq, reading response"
    }
  },
  "P-256": {
    ...
  }
}
```
with `renewal` giving the properties of the new certificate, once it has been obtained. This can
be exposed publicly as well, since - once the server is reloaded, it is part of every TLS connection.

If `mod_md` is linked with an OpenSSL v1.1.x or higher, it also exposes [certificate transparency](https://www.certificate-transparency.org) information for the new certificate. This would look like this:

```
  "renewal": {
    ...
    "scts": [
      { "logid": "747eda8331ad331091219cce254f4270c2bffd5e422008c6373579e6107bcc56",
        "signed": 'Fri, 31 May 2019 17:06:35 GMT',
        "signature" : "<more hex>",
        "signature-type" : "<algorithm name>"
      }, {
        ...
      }
    ]
```
These `scts` are signatures of Certificate Transparency Logs (CTLogs). The `logid` is the identifier
of the CTLog (source to identify the particular log are [given here](https://www.certificate-transparency.org/known-logs). The CTLog has a public key which allows verification of this signature. The purpose of this logging is [explained in detail at the certificate transparency site](https://www.certificate-transparency.org/what-is-ct).

In short, they allow anyone to monitor these CTLogs and detect certificates more easily that should not have been issued. For example, you own the domain `mydomain.com` and monitor the trusted CTLogs for certificates that contain domain names for your domain. Seeing such a new certificate, you can check your servers if they already use it, or have it in `renewal`. If neither is the case, the certificate was not requested by your server and maybe someone tricked a CA into creating it. 

# Using Lets Encrypt

The module has defaults that let you use Let's Encrypt (LE) with the least effort possible. For most people, this is the best choice available.

There is one thing that Let's Encrypt requires from you: you need to accept their [Terms of Service](https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf). `mod_md` needs to tell them that you accepted them, so you need to tell the module that you actually do! Add to you httpd configuration:

```
MDCertificateAgreement accepted
```

and you are ready to get certificates from Let's Encrypt.


# Other ACME CAs

There are other Certificate Authorities that offer ACME also. You configure them with the URL they mention in their
documentation. For example `buypass.com` offers ACME at `https://api.buypass.com/acme/directory`. To use that, you 
would configure Apache with:

```
MDCertificateAuthority https://api.buypass.com/acme/directory
```

You may configure a different CA for each of your domains, if your want.

## Known Issues with other CAs

### Buypass

Buypass issues you certificates without an account under its [Buypass GO SSL](https://community.buypass.com/t/63d4ay/buypass-go-ssl-endpoints-updated-14-05-2020) program. This works with `mod_md` with one exception: if you configure `MDMustStaple on` for a certificate, Buypass will accept the request but silently issue a certificate without this feature. Apache will detect it missing and turn around to get a new certificate. Until your limits are exhausted. Do not use `MDMustStable` with Buypass until they have fixed their server.

### Sectigo

Sectigo's Certificate Manager also offers an ACME endpoint with External Account Binding (EAB). You request
an EAB key in their web UI and configured this in Apache. They offer a multitude of operation modes in
Certificate Manager

### ZeroSSL

ZeroSSL has 1.5 modes of operating ACME. It requires a feature from the ACME standard called "External Account Binding" (EAB).
[See this for more details](#a-key-to-bind-them).

So, the first way to use ZeroSSL is to register an account at their web site and from there get the EAB key values
which you configure in your ACME client. Since mod_md v2.4.8, you can add those to your Apache ACME as well. However.
ZeroSSL has designed these as one-time-use only keys. A client can create an account with these once and only once. For
new attempts, you need to get new EAB values on the ZeroSSL site again.

This works with mod_md, if everything works the first time. If your use of ZeroSSL does not succeed for the
first certificate, the created account will not be stored permanently and the next attempt may try to create
a new account. Which is then denied by ZeroSSL.

Once you have gotten a certificate and reload your Apache, the account is persisted and everything should
from thereon work fine.

The other 0.5 modes of operation is a special access point in their "Rest API" (something apart from ACME)
where any client can get new EAB values for an unverified email address. This is a bit silly, since functionally
this is the same as managing accounts like Let's Encrypt does, only more complicated and outside of any standard.


# Basic Usage

## One on One

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
MDomain your_domain.de

<VirtualHost *:443>
    ServerName www.your_domain.de
    ServerAlias your_domain.de
    Protocols h2 http/1.1 acme-tls/1
    SSLEngine on
    ...
</VirtualHost>
```
The ```SSLCertificate*``` configurations are gone and you added a ```MDomain``` with a list of host names.

## There can be many

You can make 1 Managed Domain (MD) for several virtual hosts, like this:

```
MDomain your_domain.de your_other_domain.com even_more.org

<VirtualHost *:443>
    ServerName your_domain.de
    ...
</VirtualHost>

<VirtualHost *:443>
    ServerName your_other_domain.com
    ...
</VirtualHost>

<VirtualHost *:443>
    ServerName even_more.org
    ...
</VirtualHost>
```

This obtains _one_ certificate that carries all _three_ domain names. If you have a hundred virtual hosts, you can make one MD for all of them, _but_
  * the certificate will become large. Since it is sent to every browser on every connection, it becomes unnecessary traffic.
  * ```mod_md``` may become slow at a certain point

So, slice the domains you have into some meaningful groups and what the certificate sizes you get.

## Additional Domains

Some people, myself included, like to use these certificates also for their mail server. This is fine, since not all names in a MD are checked if they are actually used in a ```VirtualHost```. Example:

```
MDomain your_domain.de www.your_domain.de mail.your_domain.de

<VirtualHost *:443>
    ServerName www.your_domain.de
    ServerAlias your_domain.de
    SSLEngine on
    ...
</VirtualHost>
```
will obtain a certificate that is also valid for ```mail.your_domain.de``` even though your Apache will not serve any content for that.

Information on where to find the certificate files and other things, you can look up in [the file storage](#file-storage). 



# Changing Domains

During the lifetime of your domains, they will require changes. You will add new names, or remove some or even split an MD into several. ```mod_md``` will follow these changes and check, if they require new certificates or can live with the existing ones.

Keep in mind: if you do not mind a few minutes of downtime, you can always wipe everything by ```mod_md``` from your file system and start anew. There are reasonable limits on how often in the same week Let's Encrypt lets you do this. But it is always an option should you desire a radical redesign of your domains/virtualhost configurations.

### Removing Names

When you have a MD with several names and remove one, ```mod_md``` will detect that. However, if it already has a certificate covering the old name list, it will do nothing. The certificate is still valid for the new, shorter list, so why bother.

It is good practise to use the shortest domain as the first one in an MD, since this will be used as the overall name of the MD on the first setup. If you later remove this first domain, the name of the MD will stay. This may then become confusing later on. For example if you then add the domain to another MD or start a new one with it, it is not clear what outcome you expect. ```mod_md``` will find a solution, however it might then need to renew more certificates then you wanted.

### Adding Names

When you add a name to an existing MD, the module will try to get a new certificate for it. No matter if the old one is still valid.

### Moving Names

If you move a name from one MD to another, it will handle this. If you move many names from one MD to another, it _should_ also cope with it. The result is predictable when you keep the first name, I am not certain if it is fully deterministic if the first name is among them.

When in doubt, make a copy of the file system store first. Which you should anyway have in your backups, right?

### Removing an MD

When you remove a complete MD, the module will ***not*** wipe its certificates and keys. So, when you add it again (maybe it was a mistake), it will find and use them again. 

# Redirecting to ```https:```

This is a collection of advice how to use ```mod_md``` to migrate your current ```http:``` site to ```https:```. You should consider this as a site owner because:
 * It gives visitors better privacy. What you might consider non-controversial content might put people in other countries in jail.
 * It assures greatly that your visitors see the pages as you want them to. Not only does this prevent certain censorship. It also prevents alterations by companies inserting _their_ ads into _your_ site, making _them_ money. An last, but not least, it hinders spreading of malware on the internet.

## Bare Bones

I assume your Apache configuration already uses one or more ```VirtualHost```s for ["name-based"](https://httpd.apache.org/docs/current/en/vhosts/) document serving. We look at one ```VirtualHost```
and discuss some options to migrate it to ```https:```.

```
Listen 80

# stuff provided by your default installation
Include global-and-module-stuff.conf

<VirtualHost *:80>
   ServerName www.mydomain.com
   DocumentRoot "mydomain/htdocs"
   ...
</VirtualHost>
```

Which serves files (or whatever additionally you have configured) from the directory ```$ServerRoot/mydomain/htdocs``` when a browser opens ```http://mydomain/``` links.

## Phase in ```https:```

When you enable ```mod_md```, ```mod_ssl``` and ```mod_watchdog``` in your server, you can change this to the following setup:

```
Listen 80
Listen 443

# stuff provided by your default installation
Include global-and-module-stuff.conf

MDomain www.mydomain.com

<VirtualHost *:80>
   ServerName www.mydomain.com
   DocumentRoot "mydomain/htdocs"
   ...
</VirtualHost>

<VirtualHost *:443>
   ServerName www.mydomain.com
   DocumentRoot "mydomain/htdocs"
   SSLEngine on
   ...
</VirtualHost>
```

If you open links like `https://mydomain/` right away, your browser might show you an error. This happens because it takes some short amount of time to contact [Let's Encrypt](https://letsencrypt.org) and get a certificate from them that your browser trusts. After that succeeded, you will need to reload your server (mod_md tells you in the server log when this is necessary).

Assume that this worked (and if not, check [how to fix problems](#how-to-fix-problems) to find out what to do), you now see your site with ```https:``` the same as with ```http:```. If your browser still has some concerns, the reasons for that may be

 * Your default settings for ```mod_ssl``` are not considered _good enough_ by the browser
 * Your ```https:``` page still contains links/images which start with ```http:```. Which could be corrupted by someone, so your browser does not consider this safe. It wants _all_ resources to come via ```https:```.

The first concern you can address by telling ```mod_ssl``` to apply higher security standards. There are tons of example out there how to do that and even a nice [secure configuration generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/) by Mozilla.

The second cause for browser concerns are remaining ```http:``` resources included in your site. That cannot be altered by configuration changes. You need to look at your html files and change links starting with ```http://mydomain/something``` into just ```/something```. If you html is generated by an app, you'd need to check the documentation of that one on how to fix it.

## Switch Over

Assuming you did all this, your browser is happy with ```https:mydomain/```, you can bring all your visitors to the secure site automatically by adding:

```
MDRequireHttps temporary
```

to the configuration and all browser that look for resources on ```http:mydomain/``` will get _redirected_ to ```https:mydomain/```. They will still remember the ```http:``` links and, should you decide to go back and disable the migration again, no harm will be done. But if it all works out and you are committed, it is better to tell visitors that this change is permanent:

```
MDRequireHttps permanent
```

This gives users better performance and improved security as they start using ```https:``` links only.

# Ports Ports Ports

When Let's Encrypt (LE) needs to verify that you are really who you claim to be, ***their*** servers contact ***your*** server. 

They open a connection to you. And they open it on port 80 for `http-01` challenges and on port 443 for `tls-alpn-01` challenges (and they ask your DNS server for `dns-01` challenges).

When a certificate is being renewed, LE gives your Apache a menu of choices. For most certificates, it offers all 3 challenge methods. However, if you ask for a wildcard certificate, it will offer only `dns-01`. It is then the task of `mod_md` to choose one.

In order to select a challenge type, `mod_md` needs to figure out which types will work with your Apache. Each
challenge type has its own prerequisites. If your server is standing in the wild, open internet, this is relatively easy:

 * `http-01` works if your server listens on port 80.
 * `tls-alpn-01`works if your server listens on port 443, `SSLEngine` is `on` and `Protocols` contains `acme-tls/1` (relatively)
 * `dns-01` works if you have configured a `MDChallengeDns01` command and know what you do.

So, if LE offers only `A` and `B` type challenges and both do not meet the requirements, `mod_md` will give up and report an error on renewal.

However, its analysis may be faulty! Your server is unlikely to run naked in the internet. Firewalls will most likely be involved. Some people use these (and other things) to do *port mapping*.

For example, the firewall might forward all incoming connections to port 80 to the port 8888 of your Apache. In this case, `mod_md` should look for port 8888 instead of 80. The configuration for this is:

```
MDPortMap http:8888    # http: connections from LE arrive at port 8888
```

Another example is that your firewall blocks port 80. No `http:` connections can be made from the internet to your server. Your Apache might listen on port 80, but you use it only for access from your local network. In such a setup, you configure:

```
MDPortMap http:-       # http: connections from LE do not arrive at all
```

The same is possible for `https:` connections.

And yet, things can even get more interesting. One may configure a server with more than one IP address and have `VirtualHost`s that listen only to one. Some domains might be reachable from LE via `http:` and some might not. In such highly specific setups, admins need to directly configure which challenges to use:

```
<MDomain abc.com>
    MDCAChallenges http-01
</MDomain>

<MDomain xyz.com>
    MDCAChallenges tls-alpn-01
</MDomain>
```

If challenges are directly configured this way, `mod_md` will no longer guess and use the one given. You may still configure a range of challenges in order of preference:

```
<MDomain abc.com>
    MDCAChallenges tls-alpn-01 http-01
</MDomain>
```

Meaning, if offered by LE, `tls-alpn-01` will be selected, otherwise `http-01`. (And when that was also not offered, the process will fail.)

You can also use such a configuration for all your managed domains in a global setting:

```
MDCAChallenges tls-alpn-01
MDomain abc.com
MDomain xyz.com
```

In other words, all your domains should use `tls-alpn-01` for certificate renewal. And no checks please, as you know what you are doing.


# TLS ALPN Challenges

Port 443 ([see ports](#ports-ports-ports) is the one required for the challenge type `tls-alpn-01`.

This ACME challenge type is designed to fix the weaknesses of the former ```tls-sni-01``` challenge type that is no longer available. Let's Encrypt will open a TLS connection to your Apache domain for the protocol named ```acme-tls/1```. 

This protocol string is send in the application layer protocol names (ALPN) extensions of SSL.

The protocols an Apache server allows are configured with the ```Protocols``` directive. It has as default ```http/1.1```, but if you already run the HTTP/2 protocol, you will  have added ```h2```. Now, for your server to answer the new ACMEv2 challenges, you would then add it simply:

```
Protocols h2 http/1.1 acme-tls/1
```

Then, the new challenge type is usable.

# Wildcard Certificates

See the documentation of [`MDChallengeDns01`](#mdchallengedns01) for a description on how to get them.

If you want to operate a mix of wildcard certificates and other, specific certificates for sub-domains, please
see [`MDMatchNames`](#mdmatchnames).

# Dipping the Toe

If you do not want to dive head first into the world of `mod_md` - fair enough. Take an unimportant domain of yours and make a test of the temperature, see if you like it.

As described in [Basic Usage](#basic-usage), configure this domain and see if it works for you. Maybe you have a very peculiar server setup where not all defaults fit. Maybe you need to configure outgoing proxies. Or you sit behind a port mapper. Or you want to develop and test your DNS script for wildcards. Whatever.

What is helpful in such tests is to configure another endpoint at Let's Encrypt. This will not result in certificates that are recognized by browsers, but it helps in verifying the the process works. If it does, simply switch to the real ACME endpoints and get the valid certificates then.

The real ACME endpoints of Let's Encrypt have a rate limit of 50 certificates per domain per week. And this counts all sub-domins as well. So, aaa.mydomain.net and bbb.mydomain.net are part of the same limit counter. When you test your setup or debug your DNS script, you can easily run into this limit.

Just configure:

```
<MDomain test.mydomain.net>
  MDCertificateAuthority https://acme-staging-v02.api.letsencrypt.org/directory
</MDomain>
```
 
and your requests go against LE's _staging_ environment that is exactly there for these tests.



# File Storage

```mod_md``` stores all data about your managed domains, as well as the certificates and keys in the file system. If you administrate an Apache httpd server (and why else would you be reading this), it's good to know where things are.

By default, ```mod_md``` creates a sub directory inside ```ServerRoot``` named ```md```. On a typical Ubuntu installation, this would be ```/etc/apache2/md```. Inside, you'll find the following:

```
md-+--
   +- accounts             # ACME account information, one subdir/account
   +- archive              # copies of older domain data
   +- challenges           # temporary files for answering ACME challenges
   +- domains              # one subdir per MD, contains keys and certificates
   +- httpd.json           # properties of the server, e.g. which ports it listens on
   +- md_store.json        # SECRET for private key protection, store version info
   +- staging              # MD information during certificate process
   +- tmp                  # temporary holding place when activating staging info

```
When you look inside ```domains``` you see files like:

```
md/domains/your_domain.de
  +- md.json              # all info about the managed domain itself
  +- pubcert.pem          # the certificate, plus the 'chain', e.g. all intermediate ones
  +- privkey.pem          # the private key, unencrypted
  +- job.json             # details and log of the last renewal
```
All these files belong to the user that _starts_ your server and, on most platforms, are only read/writable by that user. On Ubuntu, this is ```root```. Since you probably heard that the internet is a dangerous place, the Apache ```httpd``` will switch to another user for its traffic serving processes. So, when something bad comes in, it can also use privileges from that user, not ```root```.

```mod_md``` also runs inside those _less privileged_ processes when it talks to outside servers (e.g. Let's Encrypt). That is why certain directories and files get special permissions. Again, on Ubuntu, the lesser user is called ```www-data``` and listings from a ```md``` store look like the following:

```
drwxr-xr-x  4 root     root 4096 Aug  2 15:42 accounts
drwx------ 12 root     root 4096 Aug  3 12:23 archive
drwxr-xr-x  2 www-data root 4096 Aug  2 17:02 challenges
drwx------  4 root     root 4096 Aug  3 12:23 domains
-rw-------  1 root     root   56 Aug  3 12:35 httpd.json
-rw-------  1 root     root  105 Jul 22 11:16 md_store.json
drwxr-xr-x  3 www-data root 4096 Aug  3 12:36 staging
drwx------  2 root     root 4096 Aug  3 12:23 tmp
```
if you are familiar with ```ls```, you can see that ```challenges``` and ```staging``` belong to user ```www-data``` while all other files and directories belong to ```root```. A mix is ```accounts``` that stays writable only for ```root``` but lets everyone else read.

While talking to the ACME servers ```mod_md``` needs to read account data and write challenge data (challenges) and, finally, keys and certificates (staging).

When it has finished and the server is restarted, ```mod_md``` checks if there is a complete set of data in ```staging```, reads that data, stores it in ```tmp``` and, if it all worked, makes a rename switcheroo with ```domains``` and ```archive```. It then deletes the subdir in ```staging```.

Should you ever find out that there was a mistake, you can find the old directories of your managed domains underneath ```archive```. Just remove the wrong one, copy the archived version to ```domains/your_domain.de``` (or whatever your domain is called) and restart the server again.

## How is that Secure?

The _unencrypted_ private keys (the files named ```privkey.pem```) are inside the directory ```domains``` and are only readable by ```root```. The ACME account keys, however, are readable by everyone. But that is ok, since the account keys are stored _encrypted_ (for experts: AES_256_CBC with a 48 byte key). And also the keys stored in ```staging``` are encrypted.

The 48 bytes key to decrypt these is stored in the file ```md_store.json``` which is created when ```mod_md``` initializes the store. ***You do not want to lose that file!*** If you lose it, all the certificates you have in your store become useless - even the archived ones. 

Which is maybe not as bad as it sounds, since ```mod_md``` will just start all the ACME sign-ups again and get you new ones. However ACME servers have a rate limit and if you sign up too often, the requests get denied. Be warned.

## OK, fine. But how is that secure under Windows?

The whole file ownership and permission flags thing does not apply to Windows. According to my incomplete understanding, you have specific _service users_ and define ACLs for them in the right places...but I honestly do not know.

Short: if some Windows admin has recommendations how Windows Apache installations should be tweaked for ```mod_md``` storage, please write it here or on a blog somewhere.

## But I need it somewhere else!

Not a problem. You can specify the complete path where your MD store should be located, simple use:

```
  MDStoreDir  /path/to/where/you/want
```

If you move it, change the config first, then move the directory, then restart the server right after.





# Smaller Quality of Life Changes

## MDCertificateAgreement

This used to be a configuration setting that gave people headaches sometimes. It required you to specify the
URL from Let's Encrypt for their current Terms of Service document. This broke easily after they updated
it, which rendered all existing documentation that mention the link inoperable. This was in ACMEv1.

In ACMEv2, they only require that you POST to them a bit meaning 'I accept the ToS'. I retrofitted that to the 
ACMEv1 use as well and now you configure in Apache:

```
MDCertificateAgreement accepted
```
and it will do the right thing.


## Initial Parameter Check

The consistency of parameters for a Managed Domain is now checked additionally once at server startup. This will 
immediately show problems on the status page which formerly where only detected when renewal was attempted.

## Job Persistence

All parameters of ongoing renewal jobs are persisted in between attempts. This allows ```mod_md``` to pick up 
where it was even when you restarted the server.

## Faster Startup

While mod_md will never stall your server startup - it does renewals afterwards - there were some double 
checks by mod_md in v1.1.x which are now eliminated. If you have many domains, this might be noticeable.

# Directives

* [MDomain](#mdomain)
* [\<MDomainSet\>](#mdomainset--md-specific-settings)
* [MDCAChallenges](#mdcachallenges)
* [MDCertificateAgreement](#mdcertificateagreement--terms-of-service)
* [MDCertificateAuthority](#mdcertificateauthority)
* [MDCertificateFile](#mdcertificatefile)
* [MDCertificateKeyFile](#mdcertificatekeyfile)
* [MDCertificateMonitor](#mdcertificatemonitor)
* [MDCertificateProtocol](#mdcertificateprotocol)
* [MDCertificateStatus](#mdcertificatestatus)
* [MDCheckInterval](#mdcheckinterval)
* [MDChallengeDns01](#mdchallengedns01)
* [MDChallengeDns01Version](#mdchallengedns01version)
* [MDRenewMode](#mdrenewmode--renew-mode)
* [MDMatchNames](#mdmatchnames)
* [MDMember](#mdmember)
* [MDMembers](#mdmembers)
* [MDNotifyCmd](#mdnotifycmd)
* [MDMessageCmd](#mdmessagecmd)
* [MDPortMap](#mdportmap)
* [MDPrivateKeys](#mdprivatekeys)
* [MDHttpProxy](#mdhttpproxy)
* [MDRenewWindow](#mdrenewwindow--when-to-renew)
* [MDWarnWindow](#mdwarnwindow--when-to-warn)
* [MDServerStatus](#mdserverstatus)
* [MDStapling](#mdstapling)
* [MDStapleOthers](#mdstapleothers)
* [MDStaplingKeepResponse](#mdstaplingkeepresponse)
* [MDStaplingRenewWIndow](#mdstaplingrenewwindow)
* [MDStoreDir](#mdstoredir)


## MDomain

***Define list of domain names that belong to one group***<BR/>
`MDomain dns-name [ other-dns-name... ]`

Can be repeated multiple times. All dns-names listed in a MDomain will be Subject Alternative Names in the certificate.

## \<MDomainSet\> / MD Specific Settings

***Container for directives applied to the same managed domains***<BR/>
`<MDomainSet dns-name [ other-dns-name... ]>...</MDomainSet>`

All the configuration settings discussed should be done in the global server configuration. But you can still make settings _specific_ to a particular Managed Domain:

```
<MDomainSet example.org>
    MDMember www.example.org
    MDRenewMode manual
    MDCertificateAuthority   https://someotherca.com/ACME
</MDomainSet>
```

This allows you to have one domain from Let's Encrypt and a second from some other provider. Or also Let's Encrypt, but using another protocol (version).

Since version 2.0.4, you can also use the shorter `<MDomain name>` variant. The example would then be:

```
<MDomain example.org>
    MDMember www.example.org
    MDRenewMode manual
    MDCertificateAuthority   https://someotherca.com/ACME
</MDomain>
```

## MDCAChallenges

***Type of ACME challenge***<BR/>
`MDCAChallenges name [ name ... ]`<BR/>
Default: (auto selected))

Supported by the module are the challenge methods `tls-alpn-01`, `http-01` and  `dns-01`. The module
will look at the overall configruation of the server to find out which method can be used - in this order. 

If the server listens on port 80, for example, the `http-01` method is available. The prerequisite for `dns-01` 
is a configured  `MDChallengeDns01` command. `tls-alpn-01` needs `https:` connections  and the
`acme-tls/1` protocol ([see here](#tls-alpn-challenges)).

This auto selection works for most setups. But since Apache is a very powerful server with
many configuration options, the situation is not clear for all possible cases. For example: it may
listen on multiple IP addresses where some are reachable on `https:` and some not.

If you configure `MDCAChallenges` directly, this auto selection is disabled. Instead, the module will
use the configured challenge list when talking to the ACME server (a challenge type must be offered
by the server as well). This challenges are examined in the order specified.
 

## MDCertificateAgreement / Terms of Service

When you use ```mod_md``` you become a customer of the CA (e.g. Let's Encrypt) and that means you need to read and agree to their Terms of Service, so that you understand what they offer and what they might exclude or require from you. It's a legal thing.

For your convenience, you can tell ```mod_md``` that it should tell the CA that you agree. You do that by configuring:

```
MDCertificateAgreement accepted
```
In case of Let's Encrypt, their current [Terms of Service are here](https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf). 


## MDCertificateAuthority

***The URL of the ACME CA service***<BR/>
`MDCertificateAuthority url`<BR/>
Default: `https://acme-v02.api.letsencrypt.org/directory`

The URL where the CA offers its service.<BR/>

This needs to be an absolute `http` or `https` URL or the name of a known CA. `mod_md` currently knows
the following names:

| Name | URL |
|------|-----|
| LetsEncrypt | https://acme-v02.api.letsencrypt.org/directory |
|LetsEncrypt-Test | https://acme-staging-v02.api.letsencrypt.org/directory |
| Buypass | https://api.buypass.com/acme/directory |
| Buypass-Test | https://api.test4.buypass.no/acme/directory |

The name is not case-sensitive, so you may use `letsencrypt` as well.

Since version 2.4.16, you may configure more than one CA here. For example:

```
MDCertificateAuthority letsencrypt buypass
```
The module will try letsencrypt for a number of times and then use buypass for as many attempts. Should
that also fail, letsencrypt is tried again. This works also for 3 or more CAs configured.

The number of attempts, before a failover to the next CA happens in configured via `MDRetryFailover`.

## MDCertificateProtocol

***The protocol to use with the CA***<BR/>
`MDCertificateProtocol protocol`<BR/>
Default: `ACME`

Currently only ACME (LetsEncrypt) is implemented.

## MDChallengeDns01

`MDChallengeDns01 <path to executable>`<BR/>
Default: `none`

Wildcard certificates are possible with version 2.x of `mod_md`. But they are not straight-forward. Let's Encrypt requires the `dns-01` challenge verification for those. No other is considered good enough.

When you configure a program to be called for these challenges, you may obtain them using `mod_md`. 
The program is given the argument `setup` or `teardown` followed by the domain name. 
For `setup` the challenge content is additionally given. If you set `MDChallengeDns01Version` to `2`, the challenge
is also given to the `teardown` command.

The difficulty here is that Apache cannot do that on its own. (which is also a security benefit, since corrupting a web server or the communication path to it is the scenario `dns-01` protects against). As the name implies, `dns-01` requires you to show some specific DNS records for your domain that contain some challenge data. So you need to _write_ your domain's DNS records

If you know how to do that, you can integrated this with `mod_md`. Let's say you have a script for that in `/usr/bin/acme-setup-dns` you configure Apache with:

```
MDChallengeDns01 /usr/bin/acme-setup-dns
```
and Apache will call this script when it needs to setup/teardown a DNS challenge record for a domain. 

Assuming you want a certificate for `*.mydomain.com`, mod_md will call:

```
/usr/bin/acme-setup-dns setup mydomain.com challenge-data
# this needs to remove all existing DNS TXT records for 
# _acme-challenge.mydomain.com and create a new one with 
# content "challenge-data"
```
and afterwards it will call

```
/usr/bin/acme-setup-dns teardown mydomain.com
# this needs to remove all existing DNS TXT records for 
# _acme-challenge.mydomain.com
```

Since version 2.4.21 of the module, you may configure `MDChallengeDns01` for each MDomain separately, if needed.

## MDChallengeDns01Version

`MDChallengeDns01Version 1|2`<BR/>
Default: `1`

Set the way `MDChallengeDns01` command is invoked, e.g the number and types of arguments. See `MDChallengeDns01` for the differences. This setting is global and cannot be varied per domain.


## MDCertificateFile
***A static certificate (chain) file for the MDomain***<BR/>
`MDCertificateFile path-of-the-file`<BR/>
Default: none

This is the companion to `mod_ssl`'s `SSLCertficateFile`. It behaves exactly the same as this path is handed over to mod_ssl for all `VirtualHost` definitions that are part of the MDomain. It can only by set for a specific MDomain. A typical configuration is:

```
<MDomain mydomain.com>
  MDCertificateFile /etc/ssl/mydomain.com.cert
  MDCertificateKeyFile /etc/ssl/mydomain.com.pkey
</MDomain>
```
This allows you to define Managed Domains independent of Let's Encrypt. This gives you the monitoring and status reporting of `mod_md` and things like `MDRequireHttps` when your certificate comes from somewhere else.

`MDRenewMode auto` (the default) will _not_ cause renewal attempts for such managed domains.

Both files for certificate and key need to be defined.


## MDCertificateKeyFile
***A static private key file for the MDomain***<BR/>
`MDCertificateKeyFile path-of-the-file`<BR/>
Default: none

This is the companion to `mod_ssl`'s `SSLCertficateKeyFile`. See `MDCertificateFile` for details on how it can be used to managed domains.


## MDCheckInterval
`MDCheckInterval duration`
Default: 12h

The time between certificate checks. By default, the validity and need for renewals is checked twice a day. This interval is not followed precisely. Instead the module randomly applies a +/-50% jitter to it. With the default of 12 hours, this means the actual time between runs varies between 6 and 18 hours, jittered anew every run. This helps to mitigate traffic peaks at ACME servers.

The minimum duration you may configure is 1 second. It is not recommended to use such short times in production.

## MDMatchNames

`MDMatchNames all|servernames`<BR/>
Default: `all`

The mode `all` is the behaviour as in all previous versions. Both `ServerName` and `ServerAlias` are inspected
to find the MDomain matching a `VirtualHost`. This automatically detects coverage, even when you only have added
one of the names to an MDomain.

However, this auto-magic has drawbacks in more complex setups. If you set this directive to `servernames`, only
the `ServerName` of a virtual host is used for matching. ServerAliases are disregarded then, for matching. Aliases
will still be added to the certificate obtained, unless you also run `MDMembers manual`.

Another advantage of `servernames` is that it gives you more flexibility with sub-domains. Example:

```
MDMatchNames servernames
MDomain mydomain.org *.mydomain.org
MDomain sub.mydomain.org

<VirtualHost *:443>
  ServerName mydomain.org
  ...
</VirtualHost>

<VirtualHost *:443>
  ServerName another.mydomain.org
  ...
</VirtualHost>

<VirtualHost *:443>
  ServerName sub.mydomain.org
  ...
</VirtualHost>
```

Which allows you to get a wildcard certificate for `mydomain.org`, use that also for `another.mydomain.org`,
but get a specific certificate for `sub.mydomain.org`. (wildcard certificates have special requirements to
obtain, see [here for more information](#wildcard-certificates))

## MDMember

***Additional hostname for the managed domain***<BR/>
`MDMember hostname`

Alternative to `MDomain`

## MDMembers

***Controls if `ServerAlias` name are automatically added***<BR/>
`MDMembers auto|manual`<BR/>
Default: `auto`

Defines if ServerName and ServerAlias names of a VirtualHost are automatically added to the members of a Managed Domain or not.

## MDMustStaple

`MDMustStaple on|off`<BR/>
Default: `off`

Defines if newly requested certificate should have the OCSP Must Staple flag set or not. If a certificate has this flag, the server is ***required*** to send a OCSP stapling response to every client. This only works if you configure ```mod_ssl``` to generate this (see [SSLUseStapling](https://httpd.apache.org/docs/current/en/mod/mod_ssl.html#sslusestapling) and friends).

## MDNotifyCmd

`MDNotifyCmd <path to executable>`<BR/>
Default: `none`

Define a program to be called when the certificate of a Managed Domain has been obtained/renewed. The program is called for each MD that has been processed successfully. The program should return 0 to indicate that the notification has been handled successfully, otherwise it is called again at a later point in time until it does.

## MDMessageCmd

`MDMessageCmd <path to executable> <optional-args>`<BR/>
Default: `none`

Define a program to be called when something happened concerning a managed domain. The program is given the optional-args, reason and the name of the MD as arguments. The program should return 0 to indicate that the message has been handled successfully. The reasons for which it may be called are:

 * `renewing`: event triggered before starting renew process for the managed domain. Should the command return != 0 for this reason, renew will be repeated on next cycle.
 * `challenge-setup:<type>:<domain>`: event triggered when the challenge data for a domain has been created. This is invoked before the ACME server is told to check for it. The type is one of the ACME challenge types. This is invoked for every DNS name in a MDomain. Should the command return != 0 for this reason, the renewal will be aborted and retried later as with other error conditions.
 * `renewed`: the certificate for the managed domain has been renewed successfully. Should the command return != 0 for this reason, it will be called repeatedly until it does.
 * `installed`: the certificate for the managed domain has been installed at server startup/reload and is now used. Different to all other messages, this one is invoked  while the server is still root and has according privileges. (Hint: you may use this
     to copy a certificate+key to another application's preferred location/format.)
 * `expiring`: will warn about an expiring domain that could not be renewed (or where renewal is not performed by `mod_md` itself). See `MDWarnWindow` on how to configure its timing.
 * `errored`: errors were encountered during certificate renewal. `mod_md` will continue trying.
 * `ocsp-renewed`: when MDStapling is enabled for a domain, this indicates that an OCSP response from the Certificate Authority has been updated successfully.
 * `ocsp-errored`: when MDStapling is enabled for a domain, this indicates that an error was encountered retrieving the OCSP response from the Certificate Authority. `mod_md` will continue trying.

 The `reason` and `domain` arguments are provided after any optional arguments; that is, they are currently the last two arguments.  Your program should recognize your optional arguments since a future `mod_md` might add additional arguments after `domain`.
 
 The calls are rate limited. The successful renewal will only be called once, errors will triggers this only once per hour. The warning on an expiring certificate will run only once per day.

If you have configured:

```
MDMessageCmd /etc/apache/md-message fred
```
and the Managed Domain `mydomain.com` was renewed, the program will be called with:

```
/etc/apache/md-message fred renewed mydomain.com
```

The program should not block, as `mod_md` will wait for it to finish. If the program wants more information, you could configure the `md-status` handler that hands out MD information in JSON format. See [the chapter about monitoring](#monitoring) for more details.


## MDPortMap

***Map external to internal ports***<BR/>
`MDPortMap map1 [ map2 ]`<BR/>
Default: `http:80 https:443`

With MDPortMap you can clarify on which _local_ port `http` and `https` request arrive - should your server set behind a port mapper, such as an internet modem or a firewall. 

If you use `-` for the local port, it indicates that this protocol is not available from the internet. For example, your Apache might listen to port 80, but your firewall might block it. `mod_md` needs to know this because it means that Let's Encrypt cannot send `http:` requests to your server.

## MDPrivateKeys

***Control type and size of keys***<BR/>
`MDPrivateKeys type [ params... ]`<BR/>
Default: 'RSA 2048'

Supports RSA with an optional `param` for the key length in all versions. For example, use `RSA 4096` for 4k keys.

Since version 2.4.0, you can also specify elliptic curves for ECDSA keys. Examples of such curves are `P-384` and `P-256` (also known as `secp384r1` and `secp256r1`). And there are others. These key types can only
work if the ACME CA (Let's Encrypt) supports them. And browsers as well - or whatever clients you wish to
serve.

To support new and older clients, you can have _multiple_ certificates, using different keys. Specify for example

```
MDPrivateKeys RSA secp384r1
```
to have one RSA and one ECDSA key+certificate for you domains and the SSL library will use the one
best matching your client's capabilities.



## MDHttpProxy

***The URL of the http-proxy to use***<BR/>
`MDHttpProxy url` 

Use a proxy (on `url`) to connect to the MDCertificateAuthority url. Use if your webserver has no outbound connectivity in combination with your forward proxy.

## MDRenewMode / Renew Mode

***Controls when `mod_md` will try to obtain/renew certificates***<BR/>
`MDRenewMode always|auto|manual`<BR/>
Default: `auto`

This controls how ```mod_md``` goes about renewing certificates for Managed Domains. The default is:

```
MDRenewMode  auto
```
where, unsurprisingly, ```mod_md``` will get a new certificate when needed. For a Managed Domain used in a `VirtualHost` this means a good chunk of time before the existing certificate expires. How early that is can be configured with `MDRenewWindow`.

If a Managed Domain is not used by any `VirtualHost`, the `auto` mode will not renew certificates. The same is true if the Managed Domain has a static certificate file via `MDCertificateFile`.

If you want renewal for such Managed Domains, you should set their renewal mode to `always`. 

Also, when setting renew mode to `manual` you can disable the renewal by `mod_md`.


(***Note***: ```auto``` renew mode requires ```mod_watchdog``` to be active in your server.)<BR/>
(***Note***: this was called ```MDDriveMode``` in earlier versions and that name is still available to not break existing configurations.)

## MDRenewWindow / When to renew

***Control when the certificate will be renewed***<BR/>
`MDRenewWindow duration`<BR/>
Default: 33%

If the validity of the certificate falls below `duration`, `mod_md` will get a new signed certificate.

Normally, certificates are valid for around 90 days and `mod_md` will renew them the earliest 33% of their complete lifetime before they expire (so for 90 days validity, 30 days before it expires). If you think this is not what you need, you can specify either the exact time, as in:
```
MDRenewWindow   21d
```
or as in
```
MDRenewWindow   30s
```
but 30 seconds might be cutting things a little close.<BR/>
Or you may specify another percentage:
```
MDRenewWindow   10%
```

## MDWarnWindow / When to warn

***Control when to warn about an expiring certificate***<BR/>
`MDWarnWindow duration`<BR/>
Default: 10%

Similar to `MDRenewWindow` this directive defines when you want to be warned about the  expiry of a domain's certificate. This will invoke the `MDMessageCmd` with reason `expiring`.

### When and how often does it check?

When in ```auto``` drive mode, the module will check every 12 hours at least what the status of the managed domains is and if it needs to do something. On errors, for example when the CA is unreachable, it will initially retry after some seconds. Should that continue to fail, it will back off to a maximum interval of hourly checks.

***It will contact no outside server at startup!*** All driving is done when the server is running and serving traffic. There is nothing that delays the startup/restart of your httpd.

If a Managed Domain does not have all information, it will answer all requests with a ```503 Service Unavailable``` - assuming your client even wants to talk to it (it might fall back to another vhost TLS definition, depending how your server is setup).

Expired certificates will continue being used until a replacement is available. So, when your server clock freaks out, nothing gets thrown away automatically. Also, speaking of throwing things away: ```mod_md``` keeps a copy of previous certificates/keys when it renews a domain. You have those files as part of your backups, right?

## MDRequireHttps

This is a directive to ease ```http:``` to ```https:``` migration of your Managed Domains. With

```
MDRequireHttps temporary
```

you announce that you want all traffic via ```http:``` URLs to be _redirected_ to the ```https:``` ones, for now. If you want client to no longer use the ```http:``` URLs, configure

```
MDRequireHttps permanent
```

***This only works if your domains are reachable on the standard https port 443! ***

You can achieve the same with ```mod_alias``` and some ```Redirect``` configuration, basically. If you do it yourself, please make sure to exclude the paths ```/.well-known/*``` from your redirection, otherwise ```mod_md``` might have trouble signing on new certificates.

If you set this globally, it applies to all managed domains. If you want it for a specific domain only, use

```
<MDomain xxx.yyy>
  MDRequireHttps permanent
</MDomain>
```

You still need to define a VirtualHost for port 80. If that does not exist, no redirects will happen. 

### Permanent and Security

When you configure ```MDRequireHttps permanent```, an additional security feature is automatically applied: [HSTS](https://tools.ietf.org/html/rfc6797). This adds the header `Strict-Transport-Security` to responses sent out via ```https:```. Basically, this instructs the browser to only perform secure communications with that domain. This instruction holds for the amount of time specified in the header as ```max-age```. This is about half a year as generated by ```mod_md```. 

It is therefore advisable to first test the ```MDRequireHttps temporary``` configuration and switch to ```permanent``` only once that works satisfactory. 

## MDStoreDir

***Location for the mod_md files***<BR/>
`MDStoreDir path`<BR/>
Default: `md`

This is where `mod_md` will store all the files (i.e. account key, private keys and certs etc.)<BR/>
The path is relative to `ServerRoot`.

Note that if you run multiple instances of `httpd`, each instance must have it's own directory.  

## MDBaseServer

`MDBaseServer on|off`<BR/>
Default: `off`

Controls if the base server, the one outside all ```VirtualHost```s should be managed by ```mod_md``` or not. Default is to not do this, for the very reason that it may have confusing side-effects. It is recommended that you have virtual hosts for all managed domains and do not rely on the global, fallback server configuration.

## MDServerStatus

`MDServerStatus on|off`<BR/>
Default: `on`

Controls if Managed Domains appear in the `server-status` handler of Apache.

## MDCertificateStatus

`MDCertificateStatus on|off`<BR/>
Default: `on`

Controls if Managed Domains respond to public requests for `/.httpd/certificate-status` or not.

## MDStapling

***Enable stapling for all or a particular MDomain.***<BR/>
`MDStapling on|off`<BR/>
Default: `off`

`mod_md` has its own implementation for providing OCSP stapling information. This is an 
alternative to the one provided by `mod_ssl`. For backward compatibility reasons, this is
disabled by default.

The new stapling can be switched on for all certificates on the server or for an individual MDomain. This
will replace any stapling configuration in `mod_ssl` for these hosts. When disabled, the `mod_ssl`
stapling (if configured) will do the work. This allows for a gradual shift over from one 
implementation to the other.

The stapling of `mod_md` will also work for domains where the certificates are not managed
by this module (see MDStapleOthers for how to control this). This allows use of the new stapling
without using any ACME certificate management.

## MDStapleOthers

***Enable stapling for certificates not managed by mod_md.***<BR/>
`MDStapleOthers on|off`<BR/>
Default: `on`

This setting only takes effect when `MDStapling` is enabled. It controls if `mod_md` should
also provide stapling information for certificates that are not directly controlled by it, e.g.
renewed via an ACME CA.

## MDStaplingKeepResponse

***Controls when responses are considered old and will be removed.***<BR/>
`MDStaplingKeepResponse duration`<BR/>
Default: 7d

This time window specifies when OCSP response data used in stapling shall be removed
from the store again on start up. Response information older than 7 days (default) is
deleted. This keeps the store from growing when certificates are renewed/reconfigured 
frequently.

## MDStaplingRenewWindow

***Control when the stapling responses will be renewed***<BR/>
`MDStaplingRenewWindow duration`<BR/>
Default: 33%

If the validity of the OCSP response used in stapling falls below `duration`, `mod_md` will obtain a new OCSP response.

The CA issuing a certificate commonly also operates the OCSP responder service and determines how long its
signed response about the validity of a certificate are valid. The longer a response is valid, the longer it can be cached
which mean better overall performance for everyone. The shorter the life time, the more rapidly certificate revocations 
spread to clients. Then there is overall reliability which requires responses to outlive an eventual downtime of 
OCSP responders.

By adjusting the stapling renew window you can control parts of this yourself. If you make this very short, you
gain maximum cache time, but service unavailability will affect you. A very long window will make updates
very frequent which may, driven to extremes, even affect your TLS connection setup times.

The default is chosen as 33%, which means renewal is started when only  a third of the response lifetime
is left. For a CA that issues OCSP responses with lifetime of 3 days, this means 2 days of caching and 1 day 
of renewing. A service outage would have to last full 24 hours to affect you.

Setting an absolute renew window, like `2d` (2 days), is also possible. However, since this does not
automatically adjusts to changes by the CA, this may result in renewals not taking place when needed.
 
## MDCertificateMonitor

***Adds links to the server-status page for checking the status of a certificate***<BR/>
`MDCertificateMonitor name url`<BR/>
Default: crt.sh https://crt.sh?q=

This is part of the 'server-status' HTML user interface and has nothing to do with the core
functioning itself. It defines the link offered on that page for easy checking of a certificate
monitor. The SHA256 fingerprint of the certificate is appended to the configured url.

Certificate Monitors offer supervision of Certificate Transparency (CT) Logs to
track the use of certificates for domains. The least you may see is that Let's Encrypt (or whichever
CA you have configured) has entered your certificates into the CTLogs.

## MDContactEmail / Contact Information

The ACME protocol requires you to give a contact url when you sign up. Currently, Let's Encrypt wants an email address (and it will use it to inform you about renewals or changed terms of service). ```mod_md``` uses the ```MDContactEmail``` directive email in your Apache configuration, so please specify the correct address there.  If ```MDContactEmail``` is not present, ```mod_md``` will use the ```ServerAdmin```  directive.

## MDCACertificateFile
***Sets the root (CA) certificates to use for TLS connections***<BR/>
`MDCACertificateFile path-to-pem-file`<BR/>
Default: none

This is mainly used in test setups where the module needs to connect to a test ACME
server that has its own root certificate. People who run an enterprise wide internal
CA might find a use for this, but they have probably adapted the general CA root 
store already and there is no special need.

Use "none" as path to disable explicitly.

## MDExternalAccountBinding
***Sets the external account binding (EAB) information to use***<BR/>
`MDExternalAccountBinding key-id hmac-value | json-file`
Default: none

Some ACME CAs have already customer accounts and require ACME clients to *bind* to such an existing 
account on registration. For this, they allow customers to create unique EAB values, for example in
the Web interfaces. Customers then configure their ACME clients with these values.

EAB values are 2 strings: a key identifier and a base64 encoded `HMAC` value. Use `MDExternalAccountBinding`
to provide these to a Managed Domain. As with all other configurations, you may set these globally
or on each MDomain separately.

All MDomains with the same CA and EAB value will share one local ACME account. If you configure
a new EAB value, this will register another ACME account when needed. Note that just changing the EAB
will not trigger a renewal of otherwise valid certificates.

In case you need to force a new registration, you may delete the files in the MD store for an account
and reload the server. Each account has its own directory in `md/accounts/ACME-*`. In the `account.json` file you can see the EAB setting tied to it.

EAB values require protection as they allow anyone in their possession to operate on an ACME account.
You are advised therefore to make the httpd configuration file restricted (e.g. readable for root only) OR
keep the EAB values in a separate file that you restrict access to.

```
MDExternalAccountBinding path/my-eab.json
```

would configure the module to read the actual value from the file at startup. The file has a simple JSON
format and would look like this:

```
{"kid": "kid-1", "hmac": "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"}
```

Make the file readable for root only (or what the httpd starts with) and handle your configuration
files as usual.

## MDRetryDelay
`MDRetryDelay duration`
Default: 5s

The delay on a failed renewal before the next attempt is done. This doubles on every consecutive error with a
cap of 24 hours, e.g. daily retries. Furthermore, the effective delay is randomly jiggled by +-50%. This is
done to avoid peak traffic, e.g. all ACME clients in the world starting at midnight in their time zones.

## MDRetryFailover
`MDRetryFailover n`
Default: 13

If more than one ACME CA is configured, this gives the number of failed attempts before the next
CA is used. It is recommended to have that larger than 1, so that an intermittent error does not lead
to discarding any results already achieved.

## MDStoreLocks
`MDStoreLocks on|off|duration`
Default: off

Enable this to use a lock file on server startup when `MDStoreDir` is synchronized with the
server configuration and renewed certificates are activated.

Locking is intended for setups in a cluster that have a shared file system for `MDStoreDir`. It
will protect the activation of renewed certificates when cluster nodes are restarted/reloaded
at the same time. Under the condition that the shared file system does support file locking.

The default duration to obtain the lock is 5 seconds. If the log cannot be obtained, an error is logged
and the server startup will continue. This may result in a cluster node to still use the previous
certificate afterwards. 

A higher timeout will reduce that likelihood, but may delay server startups/reloads in case the
locks are not properly handled in the underlying file system. A lock *should* only be held by a httpd
instance for a short duration and *should* be released on process termination. At least on any *nix
type host system, this is the case.

## MDProfile
`MDProfile name`
Default: none

Specify the name of a certificate profile your ACME CA supports. This will give your new certificate
the properties the CA has configured for it. Let's Encrypt issues different certificate lifetimes for
profiles.

If the CA does not support the profile, no profile will be used and you get a certificate with 
default properties - as the CA defines them. If you need certificates of a certain profile and would
let renewals rather fail otherwise, use `MDProfileMandatory`.

## MDProfileMandatory
`MDProfileMandatory on|off`
Default: off

Select if a certificate renewal should make a configured profile mandatory, e.g. fail renewal if
the CA does not support it.

# Test Suite

The repository comes with test suites. There are some unit tests using `libcheck` and a large overall test
suite that uses Apache, the LetsEncrypt ACME server and pytest in combination.

For the pytest suite you need a `boulder` installation. You clone this from the [letsencrypt github repository](https://github.com/letsencrypt/boulder) and use `docker` to run it. Read its [Development](https://github.com/letsencrypt/boulder#development) documentation on how to do that.

For the `pytest`, this is nowadays using `python3`. Please read up on your operating system on how to install python3. Commonly, you install components for it using the `pip3` command. For the test suite, you probably need:

```
> pip3 install pytest
> pip3 install pyopenssl
```

For various reasons, the test suite tests the *installed* `mod_md`:

```
> make
> make install
> make test
...
pytest
============================================================================
platform darwin -- Python 3.9.1, pytest-6.2.0, py-1.10.0, pluggy-0.13.1
mod_md: 2.4.5 [apache: 2.4.49(/opt/apache-2.4.x), mod_ssl, ACME server: pebble]
rootdir: /Users/sei/projects/mod_md
collected 304 items

test_0001_store.py ...................
...
```

The test suite will itself start the Apache (several times with varying configurations) and terminate it on shutdown.

If you did not give any more arguments to `configure`, it will detect if a `pebble` server is installed. You
may specify a path with `--with-pebble=path` or use `--with-boulder` if you have a local `boulder` ACME server
running.

It no ACME test server was detected, most of the tests will be skipped.

# Testing with Docker

You can test the module with docker:

```
> make test-docker
```

This creates a Debian sid image and installs the current apache2 package and Pebble. It copies and
builds the sources from your file system and runs the test suite.


# Testing with Pebble

Pebble is the preferred ACME test server now.

Follow the [instructions at the Pebble github repository](https://github.com/letsencrypt/pebble)
in order to install it. 

Configure mod_md to test with pebble:

```
> /configure --with-apxs=<your path to axps>/apxs --enable-werror --with-pebble
> make clean install
```

This will check if the commands `pebble` and `pebble-challtestsrv` can be found in your PATH.
Then you run:

```
mod_md> pytest
```

which will start the pebble servers, run the tests and stop them again. The log of its output
os found at `test/gen/pebble.log` for that run.

# Testing with Boulder

Boulder is the real server run by Let's Encrypt. It runs in 3 docker images and it is a bit heavy
weight just for testing mod_md. However it offers OCSP support (which pebble does not), so the
test coverage will be better overall.

Boulder has its main configuration in `docker-compose.yml` and there you will want to change

```
         environment:
            FAKE_DNS: <ip of your machine>
```
which answers all DNS requests for boulder with the address of your machine. The default value of `127.0.0.1` will not do. Boulder runs in a docker image and localhost is its own image and not your local machine where Apache listens. But for the tests to succeed, `boulder` needs to reach the Apache started by the test suite.

Start up boulder, see `All servers running. Hit ^C to kill.` after a while and start the test suite:


# The Let's Encrypt Expiration

Read this if you have problems with your Let's Encrypt certificate
with older or not-updated clients. There is an easy way to fix.

[As with everything crypto, it's always surrounded by a mist of
mystery and one is not sure to have ever understood it completely.
It's one of the technologies indistinguishable from magic.]

Luckily, all that `mod_md` does is stored in the file system. If
you look at one of your domains, you see something like this:

```
root:<path-to-md-store>/domains/eissing.org# ls -l
total 36
-rw------- 1 root root 7254 Sep 29 00:00 job.json
-rw------- 1 root root  743 Sep 29 00:00 md.json
-rw------- 1 root root 3000 Sep 29 00:00 privkey.pem
-rw------- 1 root root  500 Sep 29 00:00 privkey.secp384r1.pem
-rw------- 1 root root 5806 Sep 29 00:00 pubcert.pem
-rw------- 1 root root 5396 Sep 29 00:00 pubcert.secp384r1.pem
```
My domain `eissing.org` is configured with one RSA and one `secp384r1`
key and for each there is a `pubcert*.pem` file that contains
the certificate and its "chain".

Looking at `pubcert.pem`, there are 3(!) certificates in there.
First the one for eissing.org, then one with name `R3`, followed
by `X3`:

```
> cat pubcert.pem
-----BEGIN CERTIFICATE-----
(the certificate for eissing.org)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----
```

Running openssl on the first one gives:

```
>  openssl x509 -in le-c1.pem -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            91:2b:08:4a:cf:0c:18:a7:53:f6:d6:2e:25:a7:5f:5a
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Internet Security Research Group, CN=ISRG Root X1
        Validity
            Not Before: Sep  4 00:00:00 2020 GMT
            Not After : Sep 15 16:00:00 2025 GMT
        Subject: C=US, O=Let's Encrypt, CN=R3
    ...
```

Running openssl on the second one gives:

```
>  openssl x509 -in le-c2.pem -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            40:01:77:21:37:d4:e9:42:b8:ee:76:aa:3c:64:0a:b7
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: O=Digital Signature Trust Co., CN=DST Root CA X3
        Validity
            Not Before: Jan 20 19:14:03 2021 GMT
            Not After : Sep 30 18:14:03 2024 GMT
        Subject: C=US, O=Internet Security Research Group, CN=ISRG Root X1
     ...
```

When a client connects to your Apache, it basically sends the content of `pubcert.pem`
for the client to inspect and verify that everything can be trusted. Both `X3`
and `R3` trust the `eissing.org` certificate. So, the client needs to determine if
it can trust those. Trusting one of them is enough!

When clients check `X3`, they *SHOULD* see that this one cannot be trusted, as it has expired on 2021-09-30.

And here, very old OpenSSL or even recent gnuTLS clients give up and fail. The correct
behaviour is to then check trust for the *other* certificate that was sent to the client,
namely the `R3` one.

`R3` can be trusted, *if* the client has a recent CA root store (the trust anchors certificates
where trust always starts). So, if you have a correct client, but your CA root store has not
been updated for some time, the connection to `eissing.org` will also fail.

Why is Let's Encrypt giving us this no longer trusted `X3`? Well, they found out
that many, many old Android devices (which for a long time have not been updated nor will they
ever be) are so bad that they will trust `X3` foreva! Therefore, they still include
`X3` in your `pubcert.pem` files to allow these Android owners to stay on the internet.
Since a lot of those are in developing countries, it is not feasible for many of them to
update their phones just like that.

But Let's Encrypt could not fix the situation for everyone in the world. Someone was going
to get hurt by the expiring `X3` trust chain. And those are now the people with
faulty SSL clients or good ones with old root store.

### What can one do?

**If(!)** you can live without serving old Android devices, you can remove `X3`
from your `pubcert*.pem` files. That will make your site work for faulty clients with a
recent CA root store. And modern clients do not need `X3` anyway.

There is a script in `scripts/fix_le_pubcerts.sh` that removes the `X3` from 
pubcert*.pem files. You can run it on a directory, like:

```
> fix_le_pubcerts.sh <path-of-md-store>/domains/eissing.org
```

or you can install it as an `MDMessageCmd` in your Apache configuration:

```
  MDMessageCmd <path-to>/fix_le_pubcerts.sh <path-of-md-store>
```

which will remove `X3` whenever `mod_md` renews a certificate.

WARNING: this script was tested by me, but I give no warranties on its proper function
in your environment. Use with care. It makes copies of modified files, in case something
goes wrong.


# Licensing

Please see the file called LICENSE.


# Credits

This work is supported by an Award from MOSS, the Mozilla Open Source Support project (twice now!). Many thanks to these excellent people! You are awesome!

Test cases mostly written by my colleague @michael-koeller who made this to a good part really a test driven development. Thanks!

Stefan Eissing, greenbytes GmbH

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind. See LICENSE for details.


