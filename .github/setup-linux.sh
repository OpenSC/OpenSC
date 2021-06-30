#!/bin/bash -e

DEPS="docbook-xsl libpcsclite-dev xsltproc gengetopt libcmocka-dev help2man pcscd check clang-tidy softhsm2 pcsc-tools libtool make autoconf autoconf-archive automake libssl-dev zlib1g-dev pkg-config libreadline-dev openssl git"
if [ "$1" == "cac" ]; then
	DEPS="$DEPS libglib2.0-dev libnss3-dev gnutls-bin libusb-dev libudev-dev flex libnss3-tools"
elif [ "$1" == "oseid" ]; then
	DEPS="$DEPS socat gawk xxd"
elif [ "$1" == "piv"]; then
	DEPS="$DEPS ant cmake"
elif [ "$1" == "mingw" ]; then
	DEPS="$DEPS wine binutils-mingw-w64-i686 binutils-mingw-w64-x86-64 gcc-mingw-w64-i686 gcc-mingw-w64-x86-64 mingw-w64"
fi

# make sure we do not get prompts
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y build-essential $DEPS
