#!/bin/bash

set -ex -o xtrace

# Generic dependencies
DEPS="make /usr/bin/xsltproc docbook-style-xsl autoconf automake libtool bash-completion vim-common softhsm openssl diffutils gawk nss-softokn nss-tools gcc gcc-c++ pcsc-lite-devel readline-devel openssl-devel zlib-ng-devel libcmocka-devel"

dnf install -y 'dnf-command(config-manager)'
dnf config-manager --set-enabled crb
dnf install -y $DEPS

XFAIL_TESTS="test-pkcs11-tool-test-threads.sh"

if [ "$1" == "fips" ]; then
	echo "# userspace fips" > /etc/system-fips
	# We do not need the kernel part, but in case we ever do:
	# mkdir -p /var/tmp/userspace-fips
	# echo 1 > /var/tmp/userspace-fips/fips_enabled
	# mount --bind /var/tmp/userspace-fips/fips_enabled \
	# /proc/sys/crypto/fips_enabled
	update-crypto-policies --set FIPS

	# FIPS mode does not have implementation of 3DES and other ancient algorithms
	sed -i -e "/TESTS += sm/a XFAIL_TESTS=sm" src/tests/unittests/Makefile.am
	XFAIL_TESTS+=" test-pkcs11-tool-test.sh test-pkcs11-tool-unwrap-wrap-test.sh"
fi

# In FIPS mode, OpenSSL doesn't allow RSA-PKCS, this is hardcoded into OpenSSL
# and we cannot influence it. Hence, the test is expected to fail in FIPS mode.
if [[ -f "/proc/sys/crypto/fips_enabled" && $(cat /proc/sys/crypto/fips_enabled) == "1" ]]; then
	XFAIL_TESTS+=" test-pkcs11-tool-test.sh test-pkcs11-tool-unwrap-wrap-test.sh"
fi

sed -i -e "/XFAIL_TESTS/,$ {
  s/.*XFAIL_TESTS.*/XFAIL_TESTS=$XFAIL_TESTS/
  q
}" tests/Makefile.am

