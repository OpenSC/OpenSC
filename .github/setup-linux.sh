#!/bin/bash

set -ex -o xtrace

# Generic dependencies
DEPS="docbook-xsl xsltproc gengetopt help2man pcscd check pcsc-tools libtool make autoconf autoconf-archive automake pkg-config git"

# Add openssl or install openssl3.0
if [ "$1" != "ossl3" -a "$2" != "ossl3" -a  ]; then
	DEPS="$DEPS openssl"
fi

# 64bit or 32bit dependencies
if [ "$1" == "ix86" ]; then
	sudo dpkg --add-architecture i386
	DEPS="$DEPS gcc-multilib libpcsclite-dev:i386 libcmocka-dev:i386 libssl-dev:i386 zlib1g-dev:i386 libreadline-dev:i386 softhsm2:i386"
else
	DEPS="$DEPS libpcsclite-dev libcmocka-dev libssl-dev zlib1g-dev libreadline-dev softhsm2"
fi

if [ "$1" == "clang-tidy" ]; then
	DEPS="$DEPS clang-tidy"
elif [ "$1" == "cac" ]; then
	DEPS="$DEPS libglib2.0-dev libnss3-dev gnutls-bin libusb-dev libudev-dev flex libnss3-tools"
elif [ "$1" == "oseid" ]; then
	DEPS="$DEPS socat gawk xxd"
elif [ "$1" == "piv" -o "$1" == "isoapplet" -o "$1" == "gidsapplet" -o "$1" == "openpgp" ]; then
	if [ "$1" == "piv" ]; then
		DEPS="$DEPS cmake"
	fi
	DEPS="$DEPS ant openjdk-8-jdk maven"
elif [ "$1" == "mingw" -o "$1" == "mingw32" ]; then
	# Note, that this list is somehow magic and adding libwine, libwine:i386 or wine64
	# will make the following sections break without any useful logs. See GH#2458
	DEPS="$DEPS wine wine32 xvfb wget"
	sudo dpkg --add-architecture i386
	if [ "$1" == "mingw" ]; then
		DEPS="$DEPS binutils-mingw-w64-x86-64 gcc-mingw-w64-x86-64 mingw-w64"
	elif [ "$1" == "mingw32" ]; then
		DEPS="$DEPS binutils-mingw-w64-i686 gcc-mingw-w64-i686"
	fi
fi

# The Github's Ubuntu images since 20211122.1 are broken
# https://github.com/actions/virtual-environments/issues/4589
if [ "$1" == "mingw" -o "$1" == "mingw32" -o "$1" == "ix86" ]; then
	sudo apt install -y --allow-downgrades libpcre2-8-0=10.34-7
fi

# make sure we do not get prompts
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
sudo apt-get update
sudo apt-get install -y build-essential $DEPS

# install openssl 3.0 if needed
if [ "$1" == "ossl3" -o "$2" == "ossl3" ]; then
	./.github/setup-openssl.sh
fi

# install libressl if needed
if [ "$1" == "libressl" -o "$2" == "libressl" ]; then
	./.github/setup-libressl.sh
fi

if [ "$1" == "mingw" -o "$1" == "mingw32" ]; then
	if [ ! -f "$(winepath 'C:/Program Files/Inno Setup 5/ISCC.exe')" ]; then
		/sbin/start-stop-daemon --start --quiet --pidfile /tmp/custom_xvfb_99.pid --make-pidfile --background --exec /usr/bin/Xvfb -- :99 -ac -screen 0 1280x1024x16
		export DISPLAY=:99.0
		[ -d isetup ] || mkdir isetup
		pushd isetup
		[ -f isetup-5.5.6.exe ] || wget http://files.jrsoftware.org/is/5/isetup-5.5.6.exe
		sleep 5 # make sure the X server is ready ?
		wine isetup-5.5.6.exe /SILENT /VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART
		popd
	fi
fi
