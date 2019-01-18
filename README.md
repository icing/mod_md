
# mod_md - Everybody Spies

Copyright 2017-2019 greenbytes GmbH

This repository contains `mod_md`, a module for Apache httpd that adds support for Let's Encrypt (and other ACME CAs). 

This code here is to help people review and comment and test early versions. Issues you can raise here, general discussion is probably best at the httpd dev mailing list. The module is, in Apache terms, **experimental**, meaning features might change based on feedback by the community. It is however a complete implementation of the ACMEv1 protocol and used in production in many locations.

## NEWS: Experimental! Again!

The current releases, v1.99.x, contain new support for the ACMEv2 protocol and can *NOT* be considered
as stable as the previous releases. Please help me test this, but do expect things to go ***pling*** now and then.

For now, the ACMEv2 endpoint of  Let's Encrypt is not enabled by default. In order to do so, add

```
MDCertificateAuthority https://acme-staging-v02.api.letsencrypt.org/directory

# The 'real' ACMEv2. For now, better test with staging first.
# MDCertificateAuthority https://acme-v02.api.letsencrypt.org/directory
```
to your configuration.

For the new ```tls-alpn-01``` challenge method to work, you ***need a patched*** mod_ssl. The patches for trunk and 2.4.x versions of the Apache httpd are available in the ```patches``` directory. When you have that, you also need to extend the protocols you allow on your server:

```
Protocols h2 http/1.1 acme-tls/1
```
The last one, ```acme-tls/1```, is the new one that needs adding. You do not need ```h2```.


## Documentation

Look [on the wiki](https://github.com/icing/mod_md/wiki) for directions on how to use ```mod_md```.

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


