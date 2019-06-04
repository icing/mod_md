
# mod_md - Let's Encrypt for Apache

Copyright 2017-2019 greenbytes GmbH

This repository contains `mod_md`, a module for Apache httpd that adds support for Let's Encrypt (and other ACME CAs). 

Here, you find version 2 of the Apache Module. Apache 2.4.x ships with version 1.1.x. For a documentation of that version, [head over to the Apache documentation](https://httpd.apache.org/docs/2.4/mod/mod_md.html).

  - [Installation](#installation)
  - [Upgrading from v1.1.x](#upgrading)
  - [Lets Encrypt Migration](#lets-encrypt-migration)
  - [Monitoring](#monitoring)
  - [Using Lets Encrypt](#using-lets-encrypt)
  - [Simple Usage](#simple-usage)
  - [Changing Domains](#changing-domains)
  - [Redirecting to https](#redirecting-to-https)
  - [Ports Ports Ports](#ports-ports-ports)
  - [TLS ALPN Challenges](#tls-alpn-challenges)
  - [Wildcard Certificates](#wildcard-certificates)
  - [Dipping the Toe](#dipping-the-toe)
  - [File Storage](#file-storage)
  - [Configuration Directives](#directives)

# Installation

**mod_md requires Apache 2.4.33 or newer**_ with an installed ```apxs``` command. 2.4.33 comes with an older version of ```mod_md```, but you can build a newer one from here and install it into the server.

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

## Fedora

The plan in Fedora is to include v2.x of mod_md with Fedora 31, which is due to be released end of summer 2019.

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

Version 2-x status: unknown, see #124.


# Upgrading

Upgrading from `mod_md` v1.1.x to v2.x requires no action by you. The module will do any necessary data conversions and configuration settings have remaing compatible. Your domains should, after an upgrade, run as before without certificate being renewed - unless they are due for renewal anyway.

_Downgrading_ is ***not*** supported. There is not guarantuee that you can go back without any problems. When in doubt, make a backup of your `mod_md` store in the file system before upgrading.

## Lets Encrypt Migration

Beginning of May 2019, Let's Encrypt [announced their end-of-life plans for ACMEv1](https://community.letsencrypt.org/t/end-of-life-plan-for-acmev1/88430). Please read this carefully if you use their certificates.

The gist is:
 1. End of 2019, they will no longer allow new accounts to be created on ACMEv1
 1. Summer 2020, they will no longer allow new domains to sign up.
 1. Beginning of 2021, they will disrupt the service periodically to wake up people dragging their feet.

What does that mean for users of `mod_md`?

First of all, if you are on version 1.x, you need to upgrade to v2.x of the module. ***No upgrade will overwrite any of your existing, explicit configurations.*** The key word here is ***explicit***: If you specify values in your configuration for `MDCertificateAuthority`, the module will use this as you wrote it.

If you have ***not*** configured this, version 2.x of `mod_md` will choose the ACMEv2 protocol with Let's Encrypt *for all upcoming renewals*! If you do not want this, you should configure `MDCertificateAuthority` yourself. You can now easily see, which configuration is used for your domains in the [new monitoring features](#monitoring).

(There was some back-and-forth about the question, if the module should do this automatic switch-over. People with special network setups can be hurt by this. Maybe their servers need special configurations to reach the ACMEv2 host of Let's Encrypt. But for the vast majority of people, this migration should just work. And many people will not read this documentation anyway and only start googling when things stopped working. Knowing that things will come to a stop in 2021, it seems better to start the migration with a high chance of success than supressing it with a certainty of failure.)




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
on your server. As with `server-status` you will want to add authoriztation for this! 

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


### certificate-status

There is an experimental handler added by mod_md that gives information about current and
upcoming certificates on a domain. You invoke it like this:

```
> curl https://eissing.org/.httpd/certificate-status
{
  "valid-from": "Mon, 01 Apr 2019 06:47:43 GMT",
  "valid-until": "Sun, 30 Jun 2019 06:47:43 GMT",
  "serial": "03D02EDA041CB95BF23B030C308FDE0B35B7",
  "sha256-fingerprint" : "xx:yy:zz:..."
}
```

This is information available to everyone already as part of your TLS connections, so this does
not leak. Also, it does not show which other domains are on the server. It just allows an easier,
scripted access.

When a new certificate has been obtained, but is not activated yet, this will show:

```
{
  "valid-from": "Mon, 01 Apr 2019 06:47:43 GMT",
  "valid-until": "Sun, 30 Jun 2019 06:47:43 GMT",
  "serial": "03D02EDA041CB95BF23B030C308FDE0B35B7"
  "sha256-fingerprint" : "xx:yy:zz:..."
  "staging": {
    "valid-from": "Tue, 21 May 2019 11:53:59 GMT",
    "valid-until": "Mon, 19 Aug 2019 11:53:59 GMT",
    "serial": "FFC16E5FEFBE90805AC153D70EF9E8D3873A",
    "cert": "LS0tLS1...VRFLS0tLS0K"
    "sha256-fingerprint" : "aa:bb:cc:..."
  }
```
And ```cert``` will give the whole certificate in base64url encoding. Again, once the server reload, this certificate will be send to anyone opening a TLS conncection to this domain. No privacy is lost in announcing this beforehand. Instead, security might be gained: if you see someong getting a new certificate for your domain (as visible in the [new CT Log](https://letsencrypt.org/2019/05/15/introducing-oak-ct-log.html)), you can contact your Apache and check if it was the one responsible.

(Caveat: the path for this resource might still move based on user input and/if other servers might be interested in picking this up.)



# Using Lets Encrypt

The module has defaults that let you use Let's Encrypt (LE) with the least effort possible. For most people, this is the best choice available. These guys do an amazing job!

There is one thing that Let's Encrypt requires from you: you need to accept their [Terms of Service](https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf). `mod_md` needs to tell them that you accepted them, so you need to tell the module that you actually do! Add to you httpd configuration:

```
MDCertificateAgreement accepted
```

and you are ready to get certificates from Let's Encrypt.


### LE and ACME

`mod_md` talks to LE using a protocol name `ACME` (automated certificate management environment). This is, since March 2019, [an internet standard as RFC 8555](https://tools.ietf.org/html/rfc8555). This means is documented, stable and usable by everyone. It may be extended in the future, but this is the base set.

But, chicken and egg, LE was born before there was `ACME` and the protocol they initially designed is now referred to as `ACMEv1` and the from RFC 8555 is named `ACMEv2`. Verions v1.1.x of `mod_md` used the former only, version 2.x now supports both.

While most users will not have to care about this, there is a feature only available in `ACMEv2`: wildcard domains. If your want a certicate that matches something like `*.mydomain.net`, you need to [setup additional things](#wildcard-certificates), among them to use `ACMEv2``.


| CA | Protocol| dns names | dns wildcards | Challenges  | Cert Life   | Rate Limit |
-----|----|-----------|---------------|--------------|------------|------------|
|LE|[ACMEv1](https://acme-v01.api.letsencrypt.org/directory)|  yes      |  no         | ports 80+443, DNS| 90 days| [50/domain/week](https://letsencrypt.org/docs/rate-limits/) |
|LE|[ACMEv2](https://acme-v02.api.letsencrypt.org/directory)|  yes      | yes (dns-01)| ports 80+443, DNS| 90 days| [50/domain/week](https://letsencrypt.org/docs/rate-limits/) |
| Others? |

If you do not specify in `mod_md` which CA to use, the module will select ACMEv2. If you do not want this, you can enforce the older protocol for by:

```
MDCertificateAuthority https://acme-v01.api.letsencrypt.org/directory
```
You can also set this per domain:

```
<MDomainSet aaa.mydomain.net>
  MDCertificateAuthority https://acme-v01.api.letsencrypt.org/directory
</mDomainSet
```
which ensure that, whatever you set globally, this domain will use ACMEv1 with LE. For more information about this migration, see [upgrading](#upgrading).


### Other CAs

Other Certificate Authorities start offering ACMEv2 now also, according to some press statements. However I do not have any experiences with those.


# Simple Usage

## The Basic One

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
    SSLEngine on
    ...
</VirtualHost>

<VirtualHost *:443>
    ServerName your_other_domain.com
    SSLEngine on
    ...
</VirtualHost>

<VirtualHost *:443>
    ServerName even_more.org
    SSLEngine on
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

During the lifetime of your domains, they will require changes. You will add new names, or remove some or even split an MD into several. ```mod_md``` will follow these changes and check, if they require new certificates or can live with the exsting ones.

Keep in mind: if you do not mind a few minutes of downtime, you can always wipe everything by ```mod_md``` from your file system and start anew. There are reasonable limits on how often in the same week Let's Encrypt lets you do this. But it is always an option should you desire a radical redesign of your doains/virtualhost configurations.

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
   ServerName www.mydomain.org
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

MDomain www.mydomain.org

<VirtualHost *:80>
   ServerName www.mydomain.org
   DocumentRoot "mydomain/htdocs"
   ...
</VirtualHost>

<VirtualHost *:443>
   ServerName www.mydomain.org
   DocumentRoot "mydomain/htdocs"
   SSLEngine on
   ...
</VirtualHost>
```

If you open links like ```https://mydomain/``` right away, your browser might show you an error. This happens because it takes some short amount of time to contact [Let's Encrypt](https://letsencrypt.org) and get a certificate from them that your browser trusts. After that succeeded, you will need to reload your server (mod_md tells you in the server log when this is necessary).

Assume that this worked (and if not, check [trouble shooting](Trouble) to find out what to do), you now see your site with ```https:``` the same as with ```http:```. If your browser still has some concerns, the reasons for that may be

 * Your default settings for ```mod_ssl``` are not considered _good enough_ by the browser
 * Your ```https:``` page still contains links/images which start with ```http:```. Which could be corrupted by someone, so your browser does not consider this safe. It wants _all_ resources to come via ```https:```.

The first concern you can address by telling ```mod_ssl``` to apply higher security standards. There are tons of example out there how to do that and even a nice [secure configuration generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/) by Mozilla.

In the Apache httpd trunk (so not back ported to any release, yet), there is a short-hand for this:

```
SSLPolicy modern
```

which gives security defaults that a "modern" browser likes to see.

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

When Let's Encrypt needs to verify that you are really who you claim to be, ***their*** servers contact ***your*** server. They open a connection to you. And they open it on port 80 for `http-01` challenges and on port 443 for `tls-alpn-01` challenges.

The acutal challenge used is negotiated. `mod_md` sends our domain names to LE. LE sends a list of challenge options for these back. `mod_md` selects the one it perferes and considers _available_. It does not make sense to choose `http-01` if your Apache does not listen on port 80. Same for `tls-alpn-01` and port 443.

(The third challenge option, `dns-01`, is discussed in the chapter about [wildcard certificate](#wildcard-certificates).

If your server is not reachable on the ports needed, the domain renewal will fail. You will see a corresponding error message in [server-status](#monitoring).

OTOH, some servers do not listen on 80/443, but are nevertheless reachable on those ports. The common cause is a firewall/router that does _port mapping_. How should `mod_md` know? Well you need to tell it that:

```
    MDPortaMap 80:8001 443:8002
```
Which says: _"when someone on the internet opens port 80, it arrives at Apache on port 8001"_.

# TLS ALPN Challenges

Port 443 ([see ports](#ports-ports-ports) is the one required for the challenge type `tls-alpn-01`.

This ACME challenge type is designed to fix the weaknesses of the former ```tls-sni-01``` challenge type that is no longer available. Let's Encrypt will open a TLS connection to your Apache for the protocol named ```acme-tls/1```. 

This protocol string is send in the application layer protocol names (ALPN) extensions of SSL.

The protocols an Apache server allows are configured with the ```Protocols``` directive. It has as default ```http/1.1```, but if you already run the HTTP/2 protocol, you will  have added ```h2```. Now, for your server to answer the new ACMEv2 challenges, you would then add it simply:

```
Protocols h2 http/1.1 acme-tls/1
```

Then, the new challenge type is usable.

***HOWEVER*** (there is always a catch, is there not?): for now, you 'll also need a patched ```mod_ssl```to make this work. The patch is included here in the release, but patching and compiling ```mod_ssl``` might not be everyone's cup of tea. If you do *not* have a patched mod_ssl, you can still run the new mod_md, but  not ```tls-alpn-01``` will not work.


# Wildcard Certificates


Wildcard certificates are possible with version 2.x of `mod_md``. But they are not straight-forward. Let's Encrypt requires the `dns-01` challenge verification for those. No other is considered good enough.

The difficulty here is that Apache cannot do that on its own. (which is also a security benefit, since corrupting a web server is the scenario `dns-01` protects against). As the name implies, `dns-01` requires you to show some specific DNS records for your domain that contain some challenge data. So you need to _write_ your domain's DNS records

If you know how to do that, you can integrated this with `mod_md`. Let's say you have a scipt for that in `/usr/bin/acme-setup-dns` you configure Apache with:

```
MDChallengeDns01 /usr/bin/acme-setup-dns
```
and Apache will call this script when it needs to setup/teardown a DNS challenge record for a domain. 

Assuming you want a certificate for `*.mydomain.net`, mod_md will call:

```
/usr/bin/acme-setup-dns setup mydomain.net challenge-data
# this needs to remove all existing DNS TXT records for 
# _acme-challenge.mydomain.net and create a new one with 
# content "challenge-data"
```
and afterwards it will call

```
/usr/bin/acme-setup-dns teardown mydomain.net
# this needs to remove all existing DNS TXT records for 
# _acme-challenge.mydomain.net
```

If you DNS provider offers an interface for this, there is probably someone who has already
written such a script. Or he may provide one.

If your DNS provider does _not_ offer an interface that you can script, he _will_ offer at least a web interface where you can enter records manually. You can then configure a script that mails you the the information, so you can do it yourself. Welcome to the machine age!

Alternatively, there are setups where you run your own DNS server, just for the ACME challenges and cleverly redirect your DNS provider record to your own server. But these are not that simple and I have no good knowledge of what can be recommended.

As the very, very last resort: reconsider if you really need a wildcard certificate. If you have many subdomains on your server, putting the all into one certificate might not be feasible (or possible) and also not very efficient. The certificate gets send on each new connection, after all.

But mayby slicing your domains into smaller sets is an option. In the past, when you needed to buy certiciates and there was a lot of manual labor for it, this was probably unattractive. But with the automation in Apache, this no longer concerns you. 

But of course, in some setups, wildcard certificates are the only reasonable approach. You know best!


# Dipping the Toe

If you do not want to dive head first into the world of `mod_md` - fair enough. Take an unimportant domain of yours and make a test of the temperature, see if you like it.

As described in [Simple Usage](#simple-usage), configure this domain and see if it works for you. Maybe you have a very perculiar server setup where not all defaults fit. Maybe you need to configure outgoing proxies. Or you sit behind a port mapper. Or you want to develop and test your DNS script for wildcards. Whatever.

What is helpful in such tests is to configure another endpoint at Let's Encrypt. This will not result in certificates that are recognized by browsers, but it helps in verifying the the process works. If it does, simply switch to the real ACME endpoints and get the valid certificates then.

The real ACME endpoints of Let's Encrypt have a rate limit of 50 certificates per domain per week. And this counts all sub-domins as well. So, aaa.mydomain.net and bbb.mydomain.net are part of the same limit counter. When you test your setup or debug your DNS script, you can easily run into this limit.

Just configure:

```
<MDomainSet test.mydomain.net>
  MDCertificateAuthority https://acme-staging-v02.api.letsencrypt.org/directory
</MDomainSet
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
   +- fallback-privkey.pem # key used when no valid certificate is available
   +- fallback-cert.pem    # certificate used as long as no other is available
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
```
All these files belong to the user that _starts_ your server and, on most platforms, are only read/writeable by that user. On Ubuntu, this is ```root```. Since you probably heard that the internet is a dangerous place, the Apache ```httpd``` will switch to another user for its traffic serving processes. So, when something bad comes in, it can also use privileges from that user, not ```root```.

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
if you are familiar with ```ls```, you can see that ```challenges``` and ```staging``` belong to user ```www-data``` while all other files and directories belong to ```root```. A mix is ```accounts``` that stays writeable only for ```root``` but lets everyone else read.

While talking to the ACME servers ```mod_md``` needs to read account data and write challenge data (challenges) and, finally, keys and certificates (staging).

When it has finished and the server is restarted, ```mod_md``` checks if there is a complete set of data in ```staging```, reads that data, stores it in ```tmp``` and, if it all worked, makes a rename switcheroo with ```domains``` and ```archive```. It then deletes the subdir in ```staging```.

Should you ever find out that there was a mistake, you can find the old directories of your managed domains underneath ```archive```. Just remove the wrong one, copy the archived version to ```domains/your_domain.de``` (or whatever your domain is called) and restart the server again.

## How is that Secure?

The _unencrypted_ private keys (the files named ```privkey.pem```) are inside the directory ```domains``` and are only readable by ```root```. The ACME account keys, however, are readable by everyone. But that is ok, since the account keys are stored _encrypted_ (for experts: AES_256_CBC with a 48 byte key). And also the keys stored in ```staging``` are encrypted.

The 48 bytes key to decrypt these is stored in the file ```md_store.json``` which is created when ```mod_md``` initialises the store. ***You do not want to lose that file!*** If you lose it, all the certificates you have in your store become useless - even the archived ones. 

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

All parameters of ongoing renewal jobs are persisted inbetween attempts. This allows ```mod_md``` to pick up 
where it was even when you restarted the server.

## Faster Startup

While mod_md will never stall your server startup - it does renewals afterwards - there were some double 
checks by mod_md in v1.1.x which are now eliminated. If you have many domains, this might be noticable.

# Directives

* [MDomain](#mdomain)
* [\<MDomainSet\>](#mdomainset--md-specific-settings)
* [MDCAChallenges](#mdcachallenges)
* [MDCertificateAgreement](##mdcertificateagreement--terms-of-service)
* [MDCertificateAuthority](#mdcertificateauthority)
* [MDCertificateProtocol](#mdcertificateprotocol)
* [MDChallengeDns01](#mdchallengedns01)
* [MDDriveMode](#mddrivemode--drive-mode)
* [MDMember](#mdmember)
* [MDMembers](#mdmembers)
* [MDNotifyCmd](#mdnotifycmd)
* [MDPortMap](#mdportmap)
* [MDPrivateKeys](#mdprivatekeys)
* [MDHttpProxy](#mdhttpproxy)
* [MDRenewWindow](#mdrenewwindow--when-to-renew)
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
    MDDriveMode manual
    MDCertificateAuthority   https://someotherca.com/ACME
</MDomainSet>
```

This allows you to have one domain from Let's Encrypt and a second from some other provider. Or also Let's Encrypt, but using another protocol (version).

## MDCAChallenges

***Type of ACME challenge***<BR/>
`MDCAChallenges name [ name ... ]`<BR/>
Default: `tls-sni-01 http-01`

Currently implemented are `tls-sni-01` and `http-01` challenge methods.

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

## MDCertificateProtocol

***The protocol to use with the CA***<BR/>
`MDCertificateProtocol protocol`<BR/>
Default: `ACME`

Currently only ACME (LetsEncrypt) is implemented.

## MDChallengeDns01

`MDChallengeDns01 <path to executable>`<BR/>
Default: `none`

Define a program to be called when the `dns-01` challenge needs to be setup/torn down. The program is given the arguemnt `setup` or `teardown` followed by the domain name. For `setup` the challenge conent is additionally given. See [wildcard certificates](#wildcard-certificates) for more explanation.

## MDDriveMode / Drive Mode

***Controls when `mod_md` will try to obtain/renew certificates***<BR/>
`MDDriveMode always|auto|manual`<BR/>
Default: `auto`

```mod_md``` calls it _driving_ a protocol/domain to obtain the certificates. And there are two separate modes, the default being:

```
MDDriveMode  auto
```
where, unsurprisingly, ```mod_md``` will do its best to automate everything. The other mode is ```manual``` where mod_md will not contact the CA itself. Instead, you may use the provided command line utility ```a2md``` to perform this - separate from your httpd process.

(***Note***: ```auto``` drive mode requires ```mod_watchdog``` to be active in your server.)

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

Define a program to be called when the certificate of a Managed Domain has been obtained/renewed. The program is given the list of all MD names that have been processed successfully. The program should return 0 to indicate that the notification has been handled successfully.

## MDPortMap

***Map external to internal ports***<BR/>
`MDPortMap map1 [ map2 ]`<BR/>
Default: `80:80 443:443`

With MDPortMap you can tell it which 'Internet port' corresponds to which local port. A map is composed of external:internal port numbers.

## MDPrivateKeys

***Control type and size of keys***<BR/>
`MDPrivateKeys type [ params... ]`<BR/>
Default: 'RSA 2048'

Currently only supports RSA. `param` selects size of the key. Use `RSA 4096` for 4k keys.

## MDHttpProxy

***The URL of the http-proxy to use***<BR/>
`MDHttpProxy url` 

Use a proxy (on `url`) to connect to the MDCertificateAuthority url. Use if your webserver has no outbound connectivity in combination with your forward proxy.

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
Or you may specify another precentage:
```
MDRenewWindow   10%
```

### When and how often does it check?

When in ```auto``` drive mode, the module will check every 12 hours at least what the status of the managed domains is and if it needs to do something. On errors, for example when the CA is unreachable, it will initially retry after some seconds. Should that continue to fail, it will back off to a maximum interval of hourly checks.

***It will contact no outside server at startup!*** All driving is done when the server is running and serving traffic. There is nothing that delays the startup/restart of your httpd.

If a Managed Domain does not have all information, it will answer all requests with a ```503 Service Unavailable``` - assuming your client even wants to talk to it (it might fall back to another vhost TLS definition, depending how you server is setup).

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
<MDomainSet xxx.yyy>
  MDRequireHttps permanent
</MDomainSet>
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
The path is relevant to `ServerRoot`.

## MDBaseServer

`MDBaseServer on|off`<BR/>
Default: `off`

Controls if the base server, the one outside all ```VirtualHost```s should be managed by ```mod_md``` or not. Default is to not do this, for the very reason that it may have confusing side-effects. It is recommended that you have virtual hosts for all managed domains and do not rely on the global, fallback server configuration.

## ServerAdmin / Contact Information

Also, the ACME protocol requires you to give a contact url when you sign up. Currently, Let's Encrypt wants an email address (and it will use it to inform you about renewals or changed terms of service). ```mod_md``` uses the ```ServerAdmin``` email in your Apache configuration, so please specify the correct address there.


# Licensing

Please see the file called LICENSE.


# Credits

This work is supported by an Award from MOSS, the Mozilla Open Source Support project (twice now!). Many thanks to these excellent people! You are awesome!

Test cases mostly written by my colleague @michael-koeller who made this to a good part really a test driven development. Thanks!

Münster, 24.05.2019

Stefan Eissing, greenbytes GmbH

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind. See LICENSE for details.


