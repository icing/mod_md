
# mod_md - Everybody Spies

Copyright 2017 greenbytes GmbH

This repository contains `mod_md`, a module for Apache httpd that adds support for Let's Encrypt (and other ACME CAs). 

This code here is to help people review and comment and test before I bring it into the main Apache httpd repository. Issues you can raise here, general discussion is probably best at the httpd dev mailing list.

## Documentation

Look [on the wiki](https://github.com/icing/mod_md/wiki) for directions on how to use ```mod_md```.

## Status

***NEW***: the Apache2 PPA for ubuntu by @oerdnj, see [here](https://launchpad.net/~ondrej/+archive/ubuntu/apache2/+packages), has a patched ```mod_ssl``` just as ```mod_md``` needs it! Thanks! So, in such a server you just need to drop mod_md from here.

***v0.4.0:*** I have tested that version on ubuntu 14.04 with the PPA from @oerdnj on my live server against the read Let's Encrypt service. The first green lock in the browser, managed by ```mod_md```. We're getting close!

What you find here are **early experience versions** for people who like living on the edge and want to help me test not yet released changes.

This is not _checkout, configure and shoot_. For it to work, you need a patched mod_ssl (patch is provided in directory ```patches```), but that is about the only complication.

Also: this is not production ready, yet. There is an ever expanding test suite included against a local [boulder](https://github.com/letsencrypt/boulder) server, using the excellent [pytest](https://docs.pytest.org/en/latest/). Also, thanks to Jacob Champion, we have unit tests available when [check](https://libcheck.github.io/check/) is installed.

### Test Status

Tests have been verfied to run on MacOS and Ubuntu 16.04 under the following conditions:

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

This work is supported by an Award from MOSS, the Mozillla Open Source Support project. Many thanks to these excellent people! You are awesome!

Test cases mostly written by my colleague @michael-koeller who made this to a good part really a test driven development. Thanks!

Münster, 04.08.2017

Stefan Eissing, greenbytes GmbH

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind. See LICENSE for details.


