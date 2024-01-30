#!/bin/bash

set -ex -o xtrace

if [ -x "/bin/sudo" ]; then
	SUDO="sudo"
fi

if [ -f "/etc/fedora-release" ]; then
	. .github/setup-fedora.sh
	exit 0
fi

WINE_DEPS=""
# Generic dependencies
DEPS="docbook-xsl xsltproc gengetopt help2man pcscd check pcsc-tools libtool make autoconf autoconf-archive automake pkg-config git xxd openssl valgrind"

if [ "$1" == "clang" ]; then
	DEPS="$DEPS clang"
fi

# 64bit or 32bit dependencies
if [ "$1" == "ix86" ]; then
	DEPS="$DEPS gcc-multilib libpcsclite-dev:i386 libcmocka-dev:i386 libssl-dev:i386 zlib1g-dev:i386 libreadline-dev:i386 softhsm2:i386"
else
	DEPS="$DEPS libpcsclite-dev libcmocka-dev libssl-dev zlib1g-dev libreadline-dev softhsm2"
fi

if [ "$1" == "clang-tidy" ]; then
	DEPS="$DEPS clang-tidy"
elif [ "$1" == "cac" ]; then
	DEPS="$DEPS libglib2.0-dev libnss3-dev gnutls-bin libusb-dev libudev-dev flex libnss3-tools"
elif [ "$1" == "oseid" ]; then
	DEPS="$DEPS socat gawk"
elif [ "$1" == "piv" -o "$1" == "isoapplet" -o "$1" == "gidsapplet" -o "$1" == "openpgp" ]; then
	if [ "$1" == "piv" ]; then
		DEPS="$DEPS cmake"
	fi
	DEPS="$DEPS ant openjdk-8-jdk maven"
elif [ "$1" == "mingw" -o "$1" == "mingw32" ]; then
	# Note, that this list is somehow magic and adding libwine, libwine:i386 or wine64
	# will make the following sections break without any useful logs. See GH#2458
	WINE_DEPS="wine wine32 xvfb wget libc6:i386 libgcc-s1:i386 libstdc++6:i386"
	if [ "$1" == "mingw" ]; then
		WINE_DEPS="$WINE_DEPS binutils-mingw-w64-x86-64 gcc-mingw-w64-x86-64 mingw-w64"
	elif [ "$1" == "mingw32" ]; then
		WINE_DEPS="$WINE_DEPS binutils-mingw-w64-i686 gcc-mingw-w64-i686"
	fi
fi

# The Github Ubuntu images since 20211122.1 are broken
# https://github.com/actions/virtual-environments/issues/4589
if [ "$1" == "mingw" -o "$1" == "mingw32" -o "$1" == "ix86" ]; then
	$SUDO rm -f /etc/apt/sources.list.d/microsoft-prod.list
	$SUDO apt-get update -qq
	$SUDO apt-get purge -yqq libmono* moby* mono* php* libgdiplus libpcre2-posix3 libzip4
	$SUDO dpkg --add-architecture i386
fi

# make sure we do not get prompts
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
$SUDO apt-get update -qq

$SUDO apt-get install -y build-essential $DEPS

# install libressl if needed
if [ "$1" == "libressl" -o "$2" == "libressl" ]; then
	./.github/setup-libressl.sh &> /tmp/libressl.log
	RET=$?
	if [ $RET -ne 0 ]; then
		cat /tmp/libressl.log
		exit $RET
	fi
elif [ "$1" == "debug" -o "$2" == "debug" ]; then
	# install debug symbols
	$SUDO apt-get install -y lsb-core ubuntu-dbgsym-keyring
	echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
	$SUDO tee -a /etc/apt/sources.list.d/ddebs.list
	$SUDO apt-get update -qq
	DEP="libssl1.1-dbgsym"
	if [ -f "/usr/lib/x86_64-linux-gnu/libssl.so.3" ]; then
		DEP="libssl3-dbgsym"
	fi
	$SUDO apt-get install -y openssl-dbgsym "$DEP" softhsm2-dbgsym
fi

if [ "$1" == "mingw" -o "$1" == "mingw32" ]; then
	$SUDO apt-get install --allow-downgrades  -y $WINE_DEPS
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
