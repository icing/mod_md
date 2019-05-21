
# mod_md - Let's Encrypt for Apache

Copyright 2017-2019 greenbytes GmbH

This repository contains `mod_md`, a module for Apache httpd that adds support for Let's Encrypt (and other ACME CAs). 

This code here is to help people review and comment and test early versions. You may raise issues here, but general discussion is probably best at the httpd users/dev mailing list. 

The versions v1.1.x are ready for production and reflect what is shipped with Apache 2.4.x. The versions v1.99.x and the soon coming **v2.x** should be considered **experimental**.

## v2.x

The current pre-releases, v1.99.x, contain new support for the ACMEv2 protocol.

From v1.99.5 onwards mod_md supports ***wildcard certificates***. See the section below about details.


## Documentation

For Versions before v1.1.x and earlier, look [on the wiki](https://github.com/icing/mod_md/wiki) for directions on how to use ```mod_md```.

For Versions v2.x (1.99.x+) here are the relevant changes and new features:

### Server-Status v2.x

Apache has a standard module for monitoring [mod_status](https://httpd.apache.org/docs/2.4/mod/mod_status.html). With v2.x ```mod_md``` contributes a section and makes monitoring your domains easy. A snippet from my own server looks like this:

```
A typical server-status snipplet:
```

![A server-status with mod_md information](mod_md_status.png)

The ```Status``` column will show activity and error descriptions for certificate renewals. This should make
life easier for people to find out if everything is all right or what went wrong.

### ACMEv2 in v2.x

  * For now, the ACMEv2 endpoint of  Let's Encrypt is not enabled by default. If you want to test it on your server, you need to explicitly set:
  * 
```
MDCertificateAuthority https://acme-staging-v02.api.letsencrypt.org/directory
```
  This is the "staging" end point for testing. The certificates it hands out will not be accepted by browsers. But it's a good test.

  * If the ACMEv2 staging endpoint works for you, you can enable the *real* end point:
  * 
```
MDCertificateAuthority https://acme-v02.api.letsencrypt.org/directory
```
to your configuration. ```mod_md``` will in version 2.0 do that as the new default. This means, when you do not set this URL explicitly somewhere, your next certificates will come from the ACMEv2 endpoint of Let's Encrypt.

  * Changing the ```MDCertificateAuthority``` configuration will ***not*** invalidate the certificates you have. It only affects certificate renewal when it is time.


### Challenges in v2.x

*Challenges* are the method how Let's Encrypt (LE) verfifies that the domain is controlled by you. Only if you (or your Apache server) answers such a challenge correctly, LE will sign a new ceritficate.

The module supports the following ACME challenge types:

  * ```http-01```: the server needs to answer a special ```http:``` request correctly. Your Apache server needs to be reachable on port 80.
  * ```dns-01```: the DNS server for your domain needs to contain a special record. You need to configure a command for setup/teardown of DNS records.
  * ```tls-alpn-01```: the Apache server needs to answer a ```https:``` connection in a certain way. Your server needs to be reachable on port 443. You need to configure your server to support the ```acme-tls/1``` protocol. See description below.
 
#### Challenge Type ```tls-alpn-01```

This ACME challenge type is designed to fix the weaknesses of the former ```tls-sni-01``` challenge type that is no longer available. The ACME server will open a TLS connection to you Apache for the protocol named ```acme-tls/1```. 

This protocol string is send in the application layer protocol names (ALPN) extensions of SSL.

The protocols an Apache server allows are configured with the ```Protocols``` directive. It has as default ```http/1.1```, but if you already run the HTTP/2 protocol, you will  have added ```h2```. Now, for your server to answer the new ACMEv2 challenges, you would then add it simply:

```
Protocols h2 http/1.1 acme-tls/1
```
```mod_md``` will see this and allow the new challenge type. 

***HOWEVER*** (there is always a catch, is there not?): for now, you 'll also need a patched ```mod_ssl```to make this work. The patch is included here, but patching and compiling ```mod_ssl``` might not be everyone's cup of tea. If you do *not* have a patched mod_ssl, you can still run the new mod_md, but do not enable the ```tls-alpn-01``` challenge protocol.

### Wildcard Certificates in v2.x

Since v1.99.5 you can request wildcard certificates, e.g. ```*.mod_md.org```. These can be combined with other names for Managed Domains, just as before:

```
 MDomain mod_md.org *.mod_md.org www.mod_md.org
```

***HOWEVER***, Let's Encrypt will hand out certificates with a wildcard domain ***only*** on its ACMEv2 service and ***only*** when verified via the ```dns-01``` challenge method.

```dns-01``` means that Let's Encrypt (or another ACME CA) checks a DNS record for your domain *at the DNS server that handles your domain*. Read: Apache cannot answer such queries and there is no standardized interface to manipulate a DNS server, so the details of how to do this are very much up to you.

So, how does this work in general? ```mod_md``` has a new configuration directive:

```
MDChallengeDns01 <exectute-command>    
# example:
# MDChallengeDns01 /usr/sbin/dns01-handler
```

If you configure such a command, it will get called by ```mod_md``` with one of the two options:

```
# setup the answer to a dns-01 challenge, a TXT DNS record for 
# _acme-challenge.<domain> with the given challenge.
> dns01-handler setup <domain> <challenge-base64>

# clear a challenge answer
> dns01-handler teardown <domain>
```

This command needs then to talk to the DNS server you use. How it does this work, I have no idea! Upon success, it needs to return 0. All other return codes are considered as failure and the signup for the certificate will either try another challenge method (if available) or fail.

One more detail: the command will, on most installations, not be executed as ```root``` but was ```www-data```. Plan that into your security/authentication model.

So, no ready-made solution here. Sorry! But! There are many possible scenarios on how to set this up and I am sure that Linux distribution will think of nice ways to integrate this into their server setups.

### Smaller Quality of Life Changes

#### MDCertificateAgreement

This used to be a configuration setting that gave people headaches sometimes. It required you to specify the
URL from Let's Encrypt for their current Terms of Service document. This broke easily after they updated
it, which rendered all existing documentation that mention the link inoperable. This was in ACMEv1.

In ACMEv2, they only require that you POST to them a bit meaning 'I accept the ToS'. I retrofitted that to the 
ACMEv1 use as well and now you configure in Apache:

```
MDCertificateAgreement accepted
```
and it will do the right thing.

#### certificate-status

There is an experimental handler added by mod_md that gives information about current and
upcoming certificates on a domain. You invoke it like this:

```
> curl https://eissing.org/.httpd/certificate-status
{
  "validFrom": "Mon, 01 Apr 2019 06:47:43 GMT",
  "expires": "Sun, 30 Jun 2019 06:47:43 GMT",
  "serial": "03D02EDA041CB95BF23B030C308FDE0B35B7"
}
```

This is information available to everyone already as part of your TLS connections, so this does
not leak. Also, it does not show which other domains are on the server. It just allows an easier,
scripted access.

When a new certificate has been obtained, but is not activated yet, this will show:

```
{
  "validFrom": "Mon, 01 Apr 2019 06:47:43 GMT",
  "expires": "Sun, 30 Jun 2019 06:47:43 GMT",
  "serial": "03D02EDA041CB95BF23B030C308FDE0B35B7"
  "staging": {
    "validFrom": "Tue, 21 May 2019 11:53:59 GMT",
    "expires": "Mon, 19 Aug 2019 11:53:59 GMT",
    "serial": "FFC16E5FEFBE90805AC153D70EF9E8D3873A",
    "cert": "LS0tLS1...VRFLS0tLS0K"
  }
```
And ```cert``` will give the whole certificate in base64url encoding. Again, once the server reload, this certificate will be send to anyone opening a TLS conncection to this domain. No privacy is lost in announcing this beforehand. Instead, security might be gained: if you see someong getting a new certificate for your domain (as visible in the [new CT Log](https://letsencrypt.org/2019/05/15/introducing-oak-ct-log.html)), you can contact your Apache and check if it was the one responsible.

(Caveat: the path for this resource might still move based on user input and/if other servers might be interested in picking this up.)

#### Initial Parameter Check

The consistency of parameters for a Managed Domain is now checked additionally once at server startup. This will 
immediately show problems on the status page which formerly where only detected when renewal was attempted.

#### Job Persistence

All parameters of ongoing renewal jobs are persisted inbetween attempts. This allows ```mod_md``` to pick up 
where it was even when you restarted the server.

#### Faster Startup

While mod_md will never stall your server startup - it does renewals afterwards - there were some double 
checks by mod_md in v1.1.x which are now eliminated. If you have many domains, this might be noticable.

## Availability

The module has been backported to Apache 2.4.x branch and was released in version 2.4.33 (in the release notes, you
will see it listed as change in 2.4.30 - a release that never saw the light of day. So, in a sane world, all changes since
2.4.29 would be listed as change in 2.4.33. But release managers already carry a heavy burden. One always treats them with respect and
bows thankfully and does not mentions one's unimportant annoyances ;).

For the impatient and danger seekers: what you find here is a copy of what lives inside the Apache httpd ```trunk``` repository. While people find an occasional
hickup - mostly due to some unique aspect in the setups - several people, including myself, are running this inside a patched
2.4 Apache for months now. And successfully.  

However, this is not _checkout, configure and shoot_. For it to work, you need a patched mod_ssl (patch is provided in directory ```patches```), but that is about the only complication.

 There is an ever expanding test suite included against a local [boulder](https://github.com/letsencrypt/boulder) server, using the excellent [pytest](https://docs.pytest.org/en/latest/). Also, thanks to Jacob Champion, we have unit tests available when [check](https://libcheck.github.io/check/) is installed.

The Apache2 PPA for ubuntu by @oerdnj, see [here](https://launchpad.net/~ondrej/+archive/ubuntu/apache2/+packages), has a patched ```mod_ssl``` just as ```mod_md``` needs it! Thanks! So, in such a server you just need to drop mod_md from here.

### Test Status

Tests have been verified to run on MacOS and Ubuntu 16.04 under the following conditions:

 * the *SSL library you compile with supports ```SNI``` 
 * curl is linked against this recent *SSL lib
 * your Apache httpd installation has a patched ```mod_ssl```
 * you have a local boulder server installed and it resolved host names against your httpd (see below)

So, it's a bit tricky when your OS does not support features like ```SNI``` in its standard config.

## Install

See [2.4.x Installation](https://github.com/icing/mod_md/wiki/2.4.x-Installation) on the wiki.

See ```ChangeLog``` for details.

## Licensing

Please see the file called LICENSE.


## Credits

This work is supported by an Award from MOSS, the Mozilla Open Source Support project (twice now!). Many thanks to these excellent people! You are awesome!

Test cases mostly written by my colleague @michael-koeller who made this to a good part really a test driven development. Thanks!

Münster, 21.05.2019

Stefan Eissing, greenbytes GmbH

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind. See LICENSE for details.


