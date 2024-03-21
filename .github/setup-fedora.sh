#!/bin/bash

set -ex -o xtrace

# Generic dependencies
DEPS="make /usr/bin/xsltproc docbook-style-xsl autoconf automake libtool bash-completion vim-common softhsm openssl diffutils"

if [ "$1" == "clang" ]; then
	DEPS="$DEPS clang"
else
	DEPS="$DEPS gcc gcc-c++"
fi

# 64bit or 32bit dependencies
if [ "$1" == "ix86" ]; then
	DEPS="$DEPS pcsc-lite-devel*.i686 readline-devel*.i686 openssl-devel*.i686 zlib-devel*.i686 libcmocka-devel*.i686 glibc-devel*i686"
else
	DEPS="$DEPS pcsc-lite-devel readline-devel openssl-devel zlib-devel libcmocka-devel"
fi

sudo dnf install -y $DEPS

sed -i -e '/XFAIL_TESTS/,$ {
  s/XFAIL_TESTS.*/XFAIL_TESTS=test-pkcs11-tool-test-threads.sh test-pkcs11-tool-test.sh/
  q
}' tests/Makefile.am
