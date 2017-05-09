
# mod_md - managed domains for Apache httpd

Copyright 2017 greenbytes GmbH

This repository contains `mod_md`. 

## Status

What you find here are **early experience versions** for people who like living on the edge and want to help me test not yet released changes.

## Current Version

## Install

You need a built Apache httpd 2.4.x, including apxs and headers to compile and 
run this module. Additionally, you need an installed libjansson and libcurl. 
And additionally, you want an installed OpenSSL >=1.0.2, where libcurl is built
against.

tl;dr

## Changes

See ```ChangeLog``` for details.

## Documenation

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

## Licensing

Please see the file called LICENSE.


## Credits

This work is not yet funded.


Münster, 09.05.2017

Stefan Eissing, greenbytes GmbH

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind. See LICENSE for details.


