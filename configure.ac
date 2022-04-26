# Copyright 2019 greenbytes GmbH (https://www.greenbytes.de)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

AC_PREREQ([2.69])
AC_INIT([mod_md], [2.4.13], [stefan.eissing@greenbytes.de])

LT_PREREQ([2.2.6])
LT_INIT()
dnl See versioning rule:
dnl  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST(LT_CURRENT, 11)
AC_SUBST(LT_REVISION, 0)
AC_SUBST(LT_AGE, 6)

major=`echo $PACKAGE_VERSION |cut -d. -f1 | sed -e "s/[^0-9]//g"`
minor=`echo $PACKAGE_VERSION |cut -d. -f2 | sed -e "s/[^0-9]//g"`
patch=`echo $PACKAGE_VERSION |cut -d. -f3 | cut -d- -f1 | sed -e "s/[^0-9]//g"`

PACKAGE_VERSION_NUM=`printf "0x%02x%02x%02x" "$major" "$minor" "$patch"`

AC_SUBST(PACKAGE_VERSION_NUM)

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([subdir-objects no-define])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_HEADERS([src/config.h])

AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror],
                    [Turn on compile time warnings])],
    [werror=$enableval], [werror=no])

AC_ARG_ENABLE([unit-tests],
    [AS_HELP_STRING([--enable-unit-tests],
                    [Enable C-based unit tests (requires libcheck)])],
    [enable_unit_tests=$enableval], [enable_unit_tests=yes])

AC_ARG_WITH([apxs], [AS_HELP_STRING([--with-apxs],
    [Use APXS executable [default=check]])],
    [request_apxs=$withval], [request_apxs=check])

AC_ARG_WITH([curl], [AS_HELP_STRING([--with-curl], [Use curl from this prefix])],
    [request_curl=$withval], [request_curl=check])

AC_ARG_WITH([pebble], [AS_HELP_STRING([--with-pebble], [Use ACME server pebble for tests])],
    [request_pebble=$withval], [request_pebble=def])

AC_ARG_WITH([boulder], [AS_HELP_STRING([--with-boulder], [Use given url for boulder])],
    [request_boulder=$withval], [request_boulder=def])

AC_ARG_WITH([jansson], [AS_HELP_STRING([--with-jansson], [Use jansson from this prefix])],
    [request_jansson=$withval], [request_jansson=check])

AC_ARG_WITH([openssl], [AS_HELP_STRING([--with-openssl], [Use openssl from this prefix])],
    [request_openssl=$withval], [request_openssl=check])


# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC

# extern, we need to find where the apxs is. which then
# can tell us the various directories we need.
#
if test x"$request_apxs" = "xcheck"; then
    AC_PATH_PROG([APXS], [apxs])
    if test "x${APXS}" = "x"; then
        AC_MSG_ERROR("no APXS installation found")
    fi
else
    APXS="$request_apxs"
    AC_MSG_NOTICE("using APXS=$APXS as configured")
fi

AC_SUBST(APR)

prefix="$($APXS -q prefix)"
prefix="${prefix:-/usr}"
AC_SUBST(prefix)

exec_prefix="$($APXS -q exec_prefix)"
AC_SUBST(exec_prefix)
APR_BINDIR="$($APXS -q APR_BINDIR)"
AC_SUBST(APR_BINDIR)
sbindir="$($APXS -q sbindir)"
AC_SUBST(sbindir)
progname="$($APXS -q progname)"
AC_SUBST(progname)
libdir="$($APXS -q libdir)"
AC_SUBST(libdir)
SYSCONF_DIR="$($APXS -q sysconfdir)"
AC_SUBST(SYSCONF_DIR)
LIBEXEC_DIR="$($APXS -q LIBEXECDIR)"
AC_SUBST(LIBEXEC_DIR)

LDFLAGS="-L$libdir $LDFLAGS"
CPPFLAGS="-I$($APXS -q includedir) -I$($APXS -q APR_INCLUDEDIR) $($APXS -q EXTRA_CPPFLAGS) $CPPFLAGS"

HTTPD_VERSION="$($APXS -q HTTPD_VERSION)"
AC_SUBST(HTTPD_VERSION)

APACHECTL="$sbindir/apachectl"
if test ! -x "$APACHECTL"; then
    # rogue distros rename things! =)
    APACHECTL="$sbindir/apache2ctl"
fi
AC_SUBST(APACHECTL)

if test -x "$APACHECTL"; then
    DSO_MODULES="$($APACHECTL -t -D DUMP_MODULES | fgrep '(shared)'| sed 's/_module.*//g'|tr -d \\n)"
    AC_SUBST(DSO_MODULES)
    STATIC_MODULES="$($APACHECTL -t -D DUMP_MODULES | fgrep '(static)'| sed 's/_module.*//g'|tr -d \\n)"
    AC_SUBST(STATIC_MODULES)
else
    AC_MSG_WARN("apachectl not found in '$BINDIR', test suite will not work!")
    APACHECTL=""
fi

# We need crypto to be in our link path, check for it.
#
AC_CHECK_LIB([crypto], [SHA256_Init], , [AC_MSG_ERROR("library crypto not found")])

# We need a JSON lib, like jansson
#
if test x"$request_jansson" = "xcheck"; then
    AC_CHECK_LIB([jansson], [json_loads], , [AC_MSG_ERROR("library jansson not found")])

    AC_CHECK_HEADER([jansson.h], [],  [AC_MSG_WARN("header jansson.h not found")], [
    #include <jansson_config.h>
    #undef   JSON_INLINE
    #define JSON_INLINE
    #include <jansson.h>
    ])
    JANSSON_PREFIX=""
else
    LDFLAGS="$LDFLAGS -L$request_jansson/lib";
    CFLAGS="$CFLAGS -I$request_jansson/include";
    CPPFLAGS="$CPPFLAGS -I$request_jansson/include";
    JANSSON_PREFIX="$request_jansson"
fi


AC_CHECK_LIB([apr-1], [apr_pool_create_ex], [LIB_APR=apr-1], [AC_MSG_ERROR("library apr-1 not found")])
AC_SUBST(LIB_APR)
AC_CHECK_LIB([aprutil-1], [apr_brigade_create], [LIB_APRUTIL=aprutil-1], [AC_MSG_ERROR("library aprutil-1 not found")])
AC_SUBST(LIB_APRUTIL)

# We need a HTTP client which can talk https: and, optionally even HTTP/2
#
if test x"$request_curl" = "xcheck"; then
    AC_CHECK_LIB([curl], [curl_global_init], , [AC_MSG_ERROR("libcurl not found")])
    curl_config="curl-config"
    AC_CHECK_PROG([CURL_CONFIG],[$curl_config],[yes],[no])
    if  test "x$CURL_CONFIG" = xno; then
        curl_config="${prefix}/bin/curl-config"
        AC_CHECK_PROG([CURL_CONFIG],[$curl_config],[yes],[no])
    fi
else
    curl_config="$request_curl/bin/curl-config"
    AC_PATH_PROG([CURL_CONFIG],[$curl_config],[yes],[no])
fi

AM_CONDITIONAL([FOUND_CURL_CONFIG], [test "x$CURL_CONFIG" = xyes])
AM_COND_IF([FOUND_CURL_CONFIG],,[AC_MSG_ERROR([required program 'curl-config' not found.])])

# $curl_config is available. Does it off SSL?
curl_ssl=$( $curl_config --features | fgrep SSL )
if test "x$curl_ssl" = "x"; then
    AC_MSG_ERROR([curl from $curl_config does not support SSL.])
fi

if test x"$curl_config" = "xcurl-config"; then
    CURL_BIN="curl"
else
    CURL_BIN=$( dirname $curl_config)/curl
fi
AC_SUBST(CURL_BIN)

AC_CHECK_HEADERS([curl/curl.h])

CFLAGS=`$curl_config --cflags`" $CFLAGS"
LDFLAGS=`$curl_config --libs`" $LDFLAGS"

AC_MSG_CHECKING([for curl version >= 7.29])
AC_TRY_COMPILE([#include <curl/curlver.h>],[
#if !defined(LIBCURL_VERSION_MAJOR)
#error "Missing libcurl version"
#endif
#if LIBCURL_VERSION_MAJOR < 7
#error "Unsupported libcurl version " LIBCURL_VERSION
#endif
#if LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR < 29
#error "Unsupported libcurl version " LIBCURL_VERSION
#endif],
      [AC_MSG_RESULT(OK)
       curl_version_ok=yes],
      [AC_MSG_RESULT(FAILED)])

if test x"$curl_version_ok" = "x"; then
    AC_MSG_ERROR([curl from $curl_config must be at least version 7.29.])
fi


if test x"$request_openssl" = "xcheck"; then
    OPENSSL_BIN="${prefix}/bin/openssl"
    if test -x "$OPENSSL_BIN"; then
        : # all fine
    else
        OPENSSL_BIN=openssl
        AC_CHECK_PROG([FOUND_OPENSS_BIN],[$OPENSSL_BIN],[yes],[no])
    fi
else
    OPENSSL_BIN="$request_openssl/bin/openssl"
    LDFLAGS="$LDFLAGS -L$request_openssl/lib";
    CFLAGS="$CFLAGS -I$request_openssl/include";
    CPPFLAGS="$CPPFLAGS -I$request_openssl/include";
fi
AM_CONDITIONAL([FOUND_OPENSSL_BIN], [test "x$FOUND_OPENSSL_BIN" != xno])
AM_COND_IF([FOUND_OPENSSL_BIN],,[AC_MSG_ERROR([required program 'openssl' not found.])])
AC_SUBST(OPENSSL_BIN)


GEN_DIR="$PWD/test/gen"
AC_SUBST(GEN_DIR)

HTTP_PORT=5002
AC_SUBST(HTTP_PORT)

HTTPS_PORT=5001
AC_SUBST(HTTPS_PORT)

HTTP_PROXY_PORT=5052
AC_SUBST(HTTP_PROXY_PORT)

HTTPD_USER="$USER"
AC_SUBST(HTTPD_USER)

MODULE_SRC="$PWD/src"
AC_SUBST(MODULE_SRC)

ACME_DEF_URL=https://acme-v02.api.letsencrypt.org/directory
AC_SUBST(ACME_DEF_URL)

TAILSCALE_DEF_URL="file://localhost/var/run/tailscale/tailscaled.sock"
AC_SUBST(TAILSCALE_DEF_URL)

# it must be configurable without an ACME test server installed
ACME_TEST_TYPE="none"
ACME_TEST_URL="none"
ACME_TEST_EAB_URL="none"

if test "x$request_boulder" != "xdef"; then
    ACME_TEST_TYPE=boulder
    if test "x$request_boulder" = "xyes"; then
        ACME_TEST_URL=http://localhost:4001/directory
    else
        ACME_TEST_URL="$request_boulder"
    fi
else
    if test "x$request_pebble" = "xdef"; then
        if type "pebble" >/dev/null 2>&1; then
            # pebble seems installed, used it
            request_pebble=yes
        fi
    fi
    if test "x$request_pebble" != "xdef"; then
        ACME_TEST_TYPE=pebble
        ACME_TEST_URL="https://localhost:14000/dir"
        ACME_TEST_EAB_URL="https://localhost:14001/dir"
        if ! type "pebble" >/dev/null 2>&1; then
            AC_MSG_ERROR("'pebble' is not in your PATH")
        fi
        if ! type "pebble-challtestsrv" >/dev/null 2>&1; then
            AC_MSG_ERROR("'pebble-challtestsrv' is not in your PATH")
        fi
    fi
fi

AC_SUBST(ACME_TEST_TYPE)
AC_SUBST(ACME_TEST_URL)


WERROR_CFLAGS=""
if test "x$werror" != "xno"; then
    AX_CHECK_COMPILE_FLAG([-Wall], [WERROR_CFLAGS="$WERROR_CFLAGS -Wall"])
    AX_CHECK_COMPILE_FLAG([-Wconversion], [WERROR_CFLAGS="$WERROR_CFLAGS -Wconversion"])
    AX_CHECK_COMPILE_FLAG([-Wextra], [WERROR_CFLAGS="$WERROR_CFLAGS -Wextra"])
    AX_CHECK_COMPILE_FLAG([-Werror], [WERROR_CFLAGS="$WERROR_CFLAGS -Werror"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes], [WERROR_CFLAGS="$WERROR_CFLAGS -Wmissing-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes], [WERROR_CFLAGS="$WERROR_CFLAGS -Wstrict-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-declarations], [WERROR_CFLAGS="$WERROR_CFLAGS -Wmissing-declarations"])
    AX_CHECK_COMPILE_FLAG([-Wpointer-arith], [WERROR_CFLAGS="$WERROR_CFLAGS -Wpointer-arith"])
    # we like to use such things...
    #AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdeclaration-after-statement"])
    AX_CHECK_COMPILE_FLAG([-Wformat-security], [WERROR_CFLAGS="$WERROR_CFLAGS -Wformat-security"])
    AX_CHECK_COMPILE_FLAG([-Wwrite-strings], [WERROR_CFLAGS="$WERROR_CFLAGS -Wwrite-strings"])
    AX_CHECK_COMPILE_FLAG([-Wshadow], [WERROR_CFLAGS="$WERROR_CFLAGS -Wshadow"])
    AX_CHECK_COMPILE_FLAG([-Winline], [WERROR_CFLAGS="$WERROR_CFLAGS -Winline"])
    AX_CHECK_COMPILE_FLAG([-Wnested-externs], [WERROR_CFLAGS="$WERROR_CFLAGS -Wnested-externs"])
    AX_CHECK_COMPILE_FLAG([-Wfloat-equal], [WERROR_CFLAGS="$WERROR_CFLAGS -Wfloat-equal"])
    AX_CHECK_COMPILE_FLAG([-Wundef], [WERROR_CFLAGS="$WERROR_CFLAGS -Wundef"])
    AX_CHECK_COMPILE_FLAG([-Wendif-labels], [WERROR_CFLAGS="$WERROR_CFLAGS -Wendif-labels"])
    AX_CHECK_COMPILE_FLAG([-Wempty-body], [WERROR_CFLAGS="$WERROR_CFLAGS -Wempty-body"])
# does not make sense with APR as it prefers char* to void*
#    AX_CHECK_COMPILE_FLAG([-Wcast-align], [WERROR_CFLAGS="$WERROR_CFLAGS -Wcast-align"])
    AX_CHECK_COMPILE_FLAG([-Wvla], [WERROR_CFLAGS="$WERROR_CFLAGS -Wvla"])
    AX_CHECK_COMPILE_FLAG([-Wunreachable-code], [WERROR_CFLAGS="$WERROR_CFLAGS -Wunreachable-code"])
    AX_CHECK_COMPILE_FLAG([-Waddress], [WERROR_CFLAGS="$WERROR_CFLAGS -Waddress"])
    AX_CHECK_COMPILE_FLAG([-Wattributes], [WERROR_CFLAGS="$WERROR_CFLAGS -Wattributes"])
    AX_CHECK_COMPILE_FLAG([-Wdiv-by-zero], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdiv-by-zero"])
    AX_CHECK_COMPILE_FLAG([-Wshorten-64-to-32], [WERROR_CFLAGS="$WERROR_CFLAGS -Wshorten-64-to-32"])
    #AX_CHECK_COMPILE_FLAG([-Wno-sign-compare], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-sign-compare"])
    #AX_CHECK_COMPILE_FLAG([-Wno-unused-parameter], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-unused-parameter"])
    #AX_CHECK_COMPILE_FLAG([-Wno-shadow], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-shadow"])
    #AX_CHECK_COMPILE_FLAG([-Wno-undef], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-undef"])

    AX_CHECK_COMPILE_FLAG(["-std=c89"], [WERROR_CFLAGS="$WERROR_CFLAGS -std=c89"])
    AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdeclaration-after-statement"])

# gcc warnings, considered useful as in https://kristerw.blogspot.de/2017/09/useful-gcc-warning-options-not-enabled.html
#
    #AX_CHECK_COMPILE_FLAG(["-Wduplicated-cond"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wduplicated-cond"])
    #AX_CHECK_COMPILE_FLAG(["-Wduplicated-branches"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wduplicated-branches"])
    #AX_CHECK_COMPILE_FLAG(["-Wlogical-op"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wlogical-op"])
    #AX_CHECK_COMPILE_FLAG(["-Wrestrict"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wrestrict"])
    AX_CHECK_COMPILE_FLAG(["-Wnull-dereference"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wnull-dereference"])
    #AX_CHECK_COMPILE_FLAG(["-Wuseless-cast"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wuseless-cast"])
    #AX_CHECK_COMPILE_FLAG(["-Wjump-misses-init"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wjump-misses-init"])
    AX_CHECK_COMPILE_FLAG(["-Wdouble-promotion"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdouble-promotion"])
    AX_CHECK_COMPILE_FLAG(["-Wshadow"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wshadow"])
    AX_CHECK_COMPILE_FLAG(["-Wformat=2"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wformat=2"])

    # This is used by the APR_OFFSET macro
    AX_CHECK_COMPILE_FLAG([-Wno-null-pointer-subtraction], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-null-pointer-subtraction"])
fi
AC_SUBST(WERROR_CFLAGS)

# Do we have a pkg-config?
AC_ARG_VAR([PKGCONFIG], [pkg-config executable])
AC_PATH_PROG([PKGCONFIG], [pkg-config])

export BUILD_SUBDIRS="src test"
AC_SUBST(BUILD_SUBDIRS)

prefix="$($APXS -q prefix)"
prefix="${prefix:-/usr}"
export PREFIX="${prefix}"
LDFLAGS="$LDFLAGS -L$($APXS -q libdir)"
CPPFLAGS="$CPPFLAGS -I$($APXS -q includedir) -I$($APXS -q APR_INCLUDEDIR)"
export SYSCONF_DIR="$($APXS -q sysconfdir)"
export LIBEXEC_DIR="$($APXS -q LIBEXECDIR)"

# Should we build unit tests?
have_check=false

if test "x$enable_unit_tests" != "xno"; then
    # The Check library is needed for C-based unit tests. Only pkg-config
    # discovery is supported for it at the moment.
    AC_MSG_CHECKING([for Check to enable unit tests])

    if test "x$PKGCONFIG" != "x" && $PKGCONFIG --atleast-version='0.9.12' check; then
        CHECK_CFLAGS=`$PKGCONFIG --cflags check`
        CHECK_LIBS=`$PKGCONFIG --libs check`

        AC_SUBST(CHECK_CFLAGS)
        AC_SUBST(CHECK_LIBS)

        have_check=true
        AC_MSG_RESULT([yes])
    else
        AC_MSG_RESULT([no])
    fi
fi

AC_PATH_PROG([XMLTO], [xmlto])
AM_CONDITIONAL([BUILD_MANPAGES], [test "x$XMLTO" != "x"])

AM_CONDITIONAL([BUILD_UNIT_TESTS], [test "x$have_check" = "xtrue"])

# Checks for header files.
AC_CHECK_HEADERS([ \
    assert.h \
    stddef.h \
])

# we'd like to use this, if it exists
AC_CHECK_FUNC(arc4random_buf, [CFLAGS="$CFLAGS -DMD_HAVE_ARC4RANDOM"], [])


# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memmove memset strcasecmp strchr])

AC_CHECK_PROG([A2ENMOD],[a2enmod])

# substitution in generated files
AC_SUBST(PREFIX)
AC_SUBST(SYSCONF_DIR)
AC_SUBST(LIBEXEC_DIR)

AC_CONFIG_FILES([
    Makefile
    src/md_version.h
    src/Makefile
    test/Makefile
    test/pyhttpd/config.ini
])

AC_OUTPUT

## Determine the compiler's vendor.

COMPILER_VERSION=`"$CC" --version | head -n1 2>/dev/null`

## IBM xlC test if COMPILER_VERSION is empty
if test x"$COMPILER_VERSION" = "x"; then
   COMPILER_VERSION=`"$CC" -qversion | head -n1 2>/dev/null`
fi

## SunCC test if COMPILER_VERSION is empty
if test x"$COMPILER_VERSION" = "x"; then
   COMPILER_VERSION=`"$CC" -V | had -n1 2>&1`
fi

if test x"$COMPILER_VERSION" != "x"; then
   COMPILER_VERSION="=> $COMPILER_VERSION"
fi

AC_MSG_NOTICE([summary of build options:

    Version:        ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE
    Host type:      ${host}
    Install prefix: ${prefix}
    APXS:           ${APXS}
    HTTPD-VERSION:  ${HTTPD_VERSION}
    C compiler:     ${CC} ${COMPILER_VERSION}
    CFLAGS:         ${CFLAGS}
    WARNCFLAGS:     ${WERROR_CFLAGS}
    LDFLAGS:        ${LDFLAGS}
    LIBS:           ${LIBS}
    CPPFLAGS:       ${CPPFLAGS}
    curl            ${CURL_BIN:--}
    curl-config     ${curl_config:--}
    jansson         ${JANSSON_PREFIX:--}
    openssl         ${OPENSSL_BIN:--}
    test-server     ${ACME_TEST_URL} (${ACME_TEST_TYPE})
])
