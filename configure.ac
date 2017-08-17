# Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
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
AC_INIT([mod_md], [0.7.0], [stefan.eissing@greenbytes.de])

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

AC_ARG_WITH([serverdir], [AS_HELP_STRING([--with-serverdir],
    [Use serverdir directory for setup [default=gen/apache]])],
    [request_serverdir=$withval], [request_serverdir=$PWD/test/gen/apache])

AC_ARG_WITH([boulder], [AS_HELP_STRING([--with-boulder], [Use given url for boulder])],
    [request_boulder=$withval], [request_boulder=def])

SERVER_NAME=$(hostname -f)
AC_SUBST(SERVER_NAME)
GEN_DIR="$PWD/test/gen"
AC_SUBST(GEN_DIR)
SERVER_DIR="$request_serverdir"
AC_SUBST(SERVER_DIR)
HTTP_PORT=5002
AC_SUBST(HTTP_PORT)
HTTPS_PORT=5001
AC_SUBST(HTTPS_PORT)

HTTPD_USER="$USER"
AC_SUBST(HTTPD_USER)

MODULE_SRC="$PWD/src"
AC_SUBST(MODULE_SRC)


# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC

if test "x$werror" != "xno"; then
    AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"])
    AX_CHECK_COMPILE_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"])
    AX_CHECK_COMPILE_FLAG([-Werror], [CFLAGS="$CFLAGS -Werror"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes], [CFLAGS="$CFLAGS -Wmissing-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes], [CFLAGS="$CFLAGS -Wstrict-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-declarations], [CFLAGS="$CFLAGS -Wmissing-declarations"])
    AX_CHECK_COMPILE_FLAG([-Wpointer-arith], [CFLAGS="$CFLAGS -Wpointer-arith"])
    # we like to use such things...
    #AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [CFLAGS="$CFLAGS -Wdeclaration-after-statement"])
    AX_CHECK_COMPILE_FLAG([-Wformat-security], [CFLAGS="$CFLAGS -Wformat-security"])
    AX_CHECK_COMPILE_FLAG([-Wwrite-strings], [CFLAGS="$CFLAGS -Wwrite-strings"])
    AX_CHECK_COMPILE_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"])
    AX_CHECK_COMPILE_FLAG([-Winline], [CFLAGS="$CFLAGS -Winline"])
    AX_CHECK_COMPILE_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"])
    AX_CHECK_COMPILE_FLAG([-Wfloat-equal], [CFLAGS="$CFLAGS -Wfloat-equal"])
    AX_CHECK_COMPILE_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"])
    AX_CHECK_COMPILE_FLAG([-Wendif-labels], [CFLAGS="$CFLAGS -Wendif-labels"])
    AX_CHECK_COMPILE_FLAG([-Wempty-body], [CFLAGS="$CFLAGS -Wempty-body"])
# does not make sense with APR as it prefers char* to void*
#    AX_CHECK_COMPILE_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"])
    AX_CHECK_COMPILE_FLAG([-Wvla], [CFLAGS="$CFLAGS -Wvla"])
    AX_CHECK_COMPILE_FLAG([-Wunreachable-code], [CFLAGS="$CFLAGS -Wunreachable-code"])
    AX_CHECK_COMPILE_FLAG([-Waddress], [CFLAGS="$CFLAGS -Waddress"])
    AX_CHECK_COMPILE_FLAG([-Wattributes], [CFLAGS="$CFLAGS -Wattributes"])
    AX_CHECK_COMPILE_FLAG([-Wdiv-by-zero], [CFLAGS="$CFLAGS -Wdiv-by-zero"])
    AX_CHECK_COMPILE_FLAG([-Wshorten-64-to-32], [CFLAGS="$CFLAGS -Wshorten-64-to-32"])
    AX_CHECK_COMPILE_FLAG([-Wno-sign-compare], [CFLAGS="$CFLAGS -Wno-sign-compare"])
    AX_CHECK_COMPILE_FLAG([-Wno-unused-parameter], [CFLAGS="$CFLAGS -Wno-unused-parameter"])
    AX_CHECK_COMPILE_FLAG([-Wno-shadow], [CFLAGS="$CFLAGS -Wno-shadow"])
    AX_CHECK_COMPILE_FLAG([-Wno-undef], [CFLAGS="$CFLAGS -Wno-undef"])

    AX_CHECK_COMPILE_FLAG(["-std=c89"], [CFLAGS="$CFLAGS -std=c89"])
    AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [CFLAGS="$CFLAGS -Wdeclaration-after-statement"])
fi

# Do we have a pkg-config?
AC_ARG_VAR([PKGCONFIG], [pkg-config executable])
AC_PATH_PROG([PKGCONFIG], [pkg-config])

MD_EXPERIMENTAL=0
AC_SUBST(MD_EXPERIMENTAL)

# When experimental, default to the LetsEncrypt ACME staging endpoint
if test "x$MD_EXPERIMENTAL" = "x1"; then
    ACME_DEF_URL=https://acme-staging.api.letsencrypt.org/directory
else
    ACME_DEF_URL=https://acme-v01.api.letsencrypt.org/directory
fi
AC_SUBST(ACME_DEF_URL)

if test "x$request_boulder" = "xdef"; then
    BOULDER_URL=http://localhost:4000/directory
elif test "x${request_boulder##http}" = "x${request_boulder}"; then
    BOULDER_URL="http://${request_boulder}/directory"
else
    BOULDER_URL="$request_boulder"
fi
AC_SUBST(BOULDER_URL)
# this is always the same, so far
BOULDER_TOS=http://boulder:4000/terms/v1
AC_SUBST(BOULDER_TOS)


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

export BUILD_SUBDIRS="src test"

prefix="$($APXS -q prefix)"
prefix="${prefix:-/usr}"
export PREFIX="${prefix}"
LDFLAGS="$LDFLAGS -L$($APXS -q libdir)"
CPPFLAGS="$CPPFLAGS -I$($APXS -q includedir) -I$($APXS -q APR_INCLUDEDIR)"
export SYSCONF_DIR="$($APXS -q sysconfdir)"
export LIBEXEC_DIR="$($APXS -q LIBEXECDIR)"

HTTPD_VERSION="$($APXS -q HTTPD_VERSION)"

# We need crypto to be in our link path, check for it.
#
AC_CHECK_LIB([crypto], [SHA256_Init], , [AC_MSG_ERROR("library crypto not found")])

# We need a JSON lib, like jansson
#
AC_CHECK_LIB([jansson], [json_loads], , [AC_MSG_ERROR("library jansson not found")])

AC_CHECK_HEADER([jansson.h], [],  [AC_MSG_WARN("header jansson.h not found")], [
#include <jansson_config.h>
#undef   JSON_INLINE
#define JSON_INLINE 
#include <jansson.h>
])


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

CURL_BIN=$( dirname $curl_config)/curl
AC_SUBST(CURL_BIN)

AC_CHECK_HEADERS([curl/curl.h])

CFLAGS="$CFLAGS "`$curl_config --cflags`
LIBS="$LIBS "`$curl_config --libs`


OPENSSL_BIN="${prefix}/bin/openssl"
if test -x "$OPENSSL_BIN"; then
    : # all fine
else
    OPENSSL_BIN=openssl
    AC_CHECK_PROG([FOUND_OPENSS_BIN],[$OPENSSL_BIN],[yes],[no])
fi

AM_CONDITIONAL([FOUND_OPENSSL_BIN], [test "x$FOUND_OPENSSL_BIN" != xno])
AM_COND_IF([FOUND_OPENSSL_BIN],,[AC_MSG_ERROR([required program 'openssl' not found.])])
AC_SUBST(OPENSSL_BIN)

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

AM_CONDITIONAL([BUILD_UNIT_TESTS], [test "x$have_check" = "xtrue"])

# Checks for header files.
AC_CHECK_HEADERS([ \
    assert.h \
    stddef.h \
])

# we'd like to use this, if it exists
AC_CHECK_FUNC(arc4random, [CFLAGS="$CFLAGS -DMD_HAVE_ARC4RANDOM"], [])


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
AC_SUBST(BUILD_SUBDIRS)
AC_SUBST(SYSCONF_DIR)
AC_SUBST(LIBEXEC_DIR)

AC_CONFIG_FILES([
    Makefile
    src/md_version.h
    src/Makefile
    test/Makefile
    test/conf/global.conf
    test/conf/httpd_http.conf
    test/conf/httpd_https.conf
    test/conf/modules.conf
    test/test.ini
    test/data/test_conf_validate/test_014.conf
])

AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

    Version:        ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE
    Host type:      ${host}
    Install prefix: ${prefix}
    APXS:           ${APXS}
    HTTPD-VERSION:  ${HTTPD_VERSION}
    C compiler:     ${CC}
    CFLAGS:         ${CFLAGS}
    WARNCFLAGS:     ${WARNCFLAGS}
    LDFLAGS:        ${LDFLAGS}
    LIBS:           ${LIBS}
    CPPFLAGS:       ${CPPFLAGS}
    curl            ${CURL_BIN:--}
    curl-config     ${curl_config:--}
    openssl         ${OPENSSL_BIN:--}
])
