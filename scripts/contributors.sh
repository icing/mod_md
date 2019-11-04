#!/bin/sh
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2013-2018, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
#
# This script was inspired, partly copied and modified from the great curl project.
# see <https://github.com/curl/>
#
#

rcommit=""

if test $# -le 0; then
    rtag=$( git tag --sort=authordate | tail -n 1 )
else
    case "$1" in
        v*)
            rtag="$1"
            ;;
        *)
            rcommit=$1
            ;;
    esac
fi

if test -n "$rtag"; then
    git show ${rtag} -lw >/dev/null || exit 1
    rcommit=$( git show ${rtag} -lw |egrep '^commit '|cut -d' ' -f2 )
    echo "since-release: ${rtag}"
fi

echo "since-commit: $rcommit"
(
git log --use-mailmap $rcommit..HEAD | \
egrep -ai '(^Author|^Commit|by):' | \
cut -d: -f2- | \
cut '-d(' -f1 | \
cut '-d<' -f1 | \
tr , '\012' | \
sed 's/ at github/ on github/' | \
sed 's/ and /\n/' | \
sed -e 's/^ //' -e 's/ $//g' -e 's/@users.noreply.github.com$/ on github/'

)| \
grep -a ' ' | \
sort -fu | \
awk '
  BEGIN {
  sep = ""
  field="contributor-names: "
}

{
 num++;
 n = sprintf("%s%s%s", n, sep, $0);
 sep = ", "
 if(length(n) > 77) {
   printf("%s%s%s\n", field, p, sep);
   field="  "
   n=sprintf("%s", $0);
 }
 p=n;
}

 END {
   printf("%s%s\n", field, p);
   printf("contributor-count: %d\n", num);
 }
'
