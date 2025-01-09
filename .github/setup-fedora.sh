#!/bin/bash

set -ex -o xtrace

# Generic dependencies
DEPS="make /usr/bin/xsltproc docbook-style-xsl autoconf automake libtool bash-completion vim-common softhsm openssl diffutils openpace openpace-devel"

if [ "$1" == "clang" ]; then
	DEPS="$DEPS clang"
else
	DEPS="$DEPS gcc gcc-c++"
fi

# 64bit or 32bit dependencies
if [ "$1" == "ix86" ]; then
	DEPS="$DEPS pcsc-lite-devel*.i686 readline-devel*.i686 openssl-devel*.i686 zlib-ng-devel*.i686 libcmocka-devel*.i686 glibc-devel*i686"
else
	DEPS="$DEPS pcsc-lite-devel readline-devel openssl-devel zlib-ng-devel libcmocka-devel"
fi

sudo dnf install -y $DEPS

XFAIL_TESTS="test-pkcs11-tool-test-threads.sh test-pkcs11-tool-test.sh"

# In FIPS mode, OpenSSL doesn't allow RSA-PKCS, this is hardcoded into OpenSSL
# and we cannot influence it. Hence, the test is expected to fail in FIPS mode.
if [[ -f "/proc/sys/crypto/fips_enabled" && $(cat /proc/sys/crypto/fips_enabled) == "1" ]]; then
	XFAIL_TESTS+=" test-pkcs11-tool-unwrap-wrap-test.sh"
fi

sed -i -e "/XFAIL_TESTS/,$ {
  s/XFAIL_TESTS.*/XFAIL_TESTS=$XFAIL_TESTS/
  q
}" tests/Makefile.am
