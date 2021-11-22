#!/bin/bash

set -ex -o xtrace

if [ "$1" == "ossl3" -o "$2" == "ossl3" ]; then
	export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig;
else
	export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig;
fi

if [ "$GITHUB_EVENT_NAME" == "pull_request" ]; then
	PR_NUMBER=$(echo $GITHUB_REF | awk 'BEGIN { FS = "/" } ; { print $3 }')
	if [ "$GITHUB_BASE_REF" == "master" ]; then
		./bootstrap.ci -s "-pr$PR_NUMBER"
	else
		./bootstrap.ci -s "$GITHUB_BASE_REF-pr$PR_NUMBER"
	fi
else
	BRANCH=$(echo $GITHUB_REF | awk 'BEGIN { FS = "/" } ; { print $3 }')
	if [ "$BRANCH" == "master" ]; then
		./bootstrap
	else
		./bootstrap.ci -s "$BRANCH"
	fi
fi

if [ "$RUNNER_OS" == "macOS" ]; then
	./MacOSX/build
	exit $?
fi

if [ "$1" == "mingw" -o "$1" == "mingw32" ]; then
	if [ "$1" == "mingw" ]; then
		HOST=x86_64-w64-mingw32
	elif [ "$1" == "mingw32" ]; then
		HOST=i686-w64-mingw32
	fi
	unset CC
	unset CXX
	./configure --host=$HOST --with-completiondir=/tmp --disable-openssl --disable-readline --disable-zlib --disable-notify --prefix=$PWD/win32/opensc || cat config.log;
	make -j 2 V=1
	# no point in running tests on mingw
else
	if [ "$1" == "ix86" ]; then
		export CFLAGS="-m32"
		export LDFLAGS="-m32"
	fi
	# normal procedure

	if [ "$1" == "ossl3" -o "$2" == "ossl3" ]; then
		# without -Werror, because of rest of deprecated API
		./configure  --disable-dependency-tracking --disable-strict CFLAGS="-Wall -Wextra -Wno-unused-parameter -Wstrict-aliasing=2"
	else
		./configure  --disable-dependency-tracking
	fi
	make -j 2 V=1
	# 32b build has some issues to find openssl correctly
	if [ "$1" != "ix86" ]; then
		make check
	fi
fi

# this is broken in old ubuntu
if [ "$1" == "dist" ]; then
	if [ "$1" == "ossl3" -o "$2" == "ossl3" ]; then
		make distcheck DISTCHECK_CONFIGURE_FLAGS="--disable-strict CFLAGS=\"-Wall -Wextra -Wno-unused-parameter -Wstrict-aliasing=2\""
	else
		make distcheck
	fi
	make dist
fi

sudo make install
if [ "$1" == "mingw" -o "$1" == "mingw32" ]; then
	# pack installed files
	wine "C:/Program Files/Inno Setup 5/ISCC.exe" win32/OpenSC.iss
fi
