
# mod_md - Everybody Spies

Copyright 2017-2019 greenbytes GmbH

This repository contains `mod_md`, a module for Apache httpd that adds support for Let's Encrypt (and other ACME CAs). 

This code here is to help people review and comment and test early versions. Issues you can raise here, general discussion is probably best at the httpd dev mailing list. The module is, in Apache terms, **experimental**, meaning features might change based on feedback by the community. It is however a complete implementation of the ACMEv1 protocol and used in production in many locations.

## NEWS: Experimental! Again!

The current releases, v1.99.x, contain new support for the ACMEv2 protocol and can *NOT* be considered
as stable as the previous releases. Please help me test this, but do expect things to go ***pling*** now and then.


For the new ```tls-alpn-01``` challenge method to work, you ***need a patched*** mod_ssl. The patches for trunk and 2.4.x versions of the Apache httpd are available in the ```patches``` directory. When you have that, you also need to extend the protocols you allow on your server:

```
Protocols h2 http/1.1 acme-tls/1
```
The last one, ```acme-tls/1```, is the new one that needs adding. You do not need ```h2```.


## Documentation

For Versions before v1.1.x and earlier, look [on the wiki](https://github.com/icing/mod_md/wiki) for directions on how to use ```mod_md```.

For Versions 1.99.x here are a summary of the changes which will be merged into the wiki once this version becomes stable:

### Base Setup in 1.99.x

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

### Challenges in v1.99.x

*Challenges* are the method how Let's Encrypt (LE) verfifies that the domain is controlled by you. Only if you (or your Apache server) answers such a challenge correctly, LE will sign a new ceritficate.

ACMEv1 and ACMEv2 have different challenge methods they allow:

  * ```http-01```: the server needs to answer a special ```http:``` request correctly. Supported on ACME v1+v2, your Apache server needs to be reachable on port 80.
  * ```dns-01```: the DNS server for your domain needs to contain a special record. Supported on ACME v1+v2, but not supported by Apache (yet).
  * ```tls-sni-01```: the Apache server needs to answer a ```https:``` connection in a certain way. Supported initialy on ACME v1, but disabled for security reasons.
  * ```tls-alpn-01```: the Apache server needs to answer a ```https:``` connection in a certain way. Supported on ACME v2, server needs to be reachable on port 443.
 
To summarize: with ```mod_md``` version 1.x you needed port 80 to be open to get LE certificates. With version 2.x you can continue to do that. But you can also configure the new challenge method and no longer need port 80. See below how this works.

#### Challenge Type ```tls-alpn-01```

This ACME v2 challenge type is designed to fix the weaknesses of the former ```tls-sni-01``` challenge type. For that, amongst other changes, it opens a TLS connection to you Apache for the protocol named 'acme-tls/1'. 

This protocol string is send in the application layer protocol names (ALPN) extensions of SSL.
No server that is not prepared for ACME challenges will ever answer that protocol. That makes it harder for cheaters so somehow fake the challenge answer.

The protocols that your Apache server allows are configured with the ```Protocols``` directive. It has as default ```http/1.1```, but if you already run the HTTP/2 protocol, you will  have added ```h2``` already. Now, for your server to answer the new ACMEv2 challenges, you would then add it simply:

```
Protocols h2 http/1.1 acme-tls/1
```
```mod_md``` will see that and use the new challenge type. 

***HOWEVER*** (there is always a catch, is there not?): for now, you 'll also need a patched ```mod_ssl```to make this work. The patch is included here, but patching and compiling ```mod_ssl``` might not be everyone's cup of tea. If you do *not* have a patched mod_ssl, you can still run the new mod_md, but do not enable the ```tls-alpn-01``` challenge protocol.

## Status

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

This work is supported by an Award from MOSS, the Mozilla Open Source Support project. Many thanks to these excellent people! You are awesome!

Test cases mostly written by my colleague @michael-koeller who made this to a good part really a test driven development. Thanks!

Münster, 07.01.2019

Stefan Eissing, greenbytes GmbH

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind. See LICENSE for details.


