#!/bin/bash

TOP=/apache-httpd
DATADIR=$TOP/data

fail() {
  echo "$@"
  exit 1
}

needs_update() {
  local ref_file="$1"
  local check_dir="$2"
  if test ! -f "$ref_file"; then
    return 0
  fi
  find "$check_dir" -type f -a -newer "$ref_file" -o -type d -name .git -prune -a -false |
  while read fname; do
    return 0
  done
  return 1
}

PREFIX=$(apxs -q exec_prefix)
if test ! -d $PREFIX; then
    fail "apache install prefix not found: $PREFIX"
fi

# remove some stuff that accumulates
LOG_DIR=$(apxs -q logfiledir)
rm -f $LOG_DIR/*

cd "$TOP/mod_md" ||fail
if needs_update .installed .; then
  rm -f .installed
  if test ! -f configure -o configure.ac -nt configure; then
    autoreconf -i ||fail
  fi
  if test ! -d Makefile -o ./configure -nt Makefile; then
    ./configure || fail
    touch ./configure
  fi
  make clean||fail
  make ||fail
  find .
  touch .installed
fi
make install ||fail
#pytest -vvv -k test_300_021 || cat test/gen/apache/logs/error_log
pytest
