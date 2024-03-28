#!/bin/bash

set -ex -o xtrace

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig;

if [ -x "/bin/sudo" ]; then
	SUDO="sudo"
fi

if [ "$GITHUB_EVENT_NAME" == "pull_request" ]; then
	PR_NUMBER=$(echo $GITHUB_REF | awk 'BEGIN { FS = "/" } ; { print $3 }')
	if [ "$GITHUB_BASE_REF" == "master" ]; then
		SUFFIX="-pr$PR_NUMBER"
	else
		SUFFIX="$GITHUB_BASE_REF-pr$PR_NUMBER"
	fi
else
	BRANCH=$(echo $GITHUB_REF | awk 'BEGIN { FS = "/" } ; { print $3 }')
	if [ "$BRANCH" != "master" ]; then
		SUFFIX="$BRANCH"
	fi
fi
if [ -n "$SUFFIX" ]; then
	./bootstrap.ci -s "$SUFFIX"
else
	./bootstrap
fi

if [ "$RUNNER_OS" == "macOS" ]; then
	./MacOSX/build
	exit $?
fi

if [ "$1" == "mingw" -o "$1" == "mingw32" ]; then
	mkdir -p src/minidriver/CNG
	wget https://raw.githubusercontent.com/open-eid/minidriver/master/cardmod.h -O src/minidriver/CNG/cardmod.h
	if [ "$1" == "mingw" ]; then
		HOST=x86_64-w64-mingw32
	elif [ "$1" == "mingw32" ]; then
		HOST=i686-w64-mingw32
	fi
	unset CC
	unset CXX
	CFLAGS="-I$PWD/src/minidriver/CNG -Wno-error=unknown-pragmas" \
	CPPFLAGS="-DNTDDI_VERSION=0x06010000" \
	./configure --host=$HOST --with-completiondir=/tmp --disable-openssl --disable-readline --disable-zlib --enable-minidriver --enable-notify --prefix=$PWD/win32/opensc || cat config.log;
	make -j 4 V=1
	# no point in running tests on mingw
else
	if [ "$1" == "ix86" ]; then
		export CFLAGS="-m32"
		export LDFLAGS="-m32"
	fi
	# normal procedure

	CONFIGURE_FLAGS="--disable-dependency-tracking --enable-doc"
	if [ "$1" == "piv-sm" ]; then
		CONFIGURE_FLAGS="$CONFIGURE_FLAGS --enable-piv-sm"
	fi
	if [ "$1" == "valgrind" -o "$2" == "valgrind" ]; then
		CONFIGURE_FLAGS="$CONFIGURE_FLAGS --disable-notify --enable-valgrind"
	fi
	if [ "$1" == "no-shared" ]; then
		CONFIGURE_FLAGS="$CONFIGURE_FLAGS --disable-shared"
	fi
	if [ "$1" == "no-openssl" ]; then
		CONFIGURE_FLAGS="$CONFIGURE_FLAGS --disable-openssl"
	fi
	export CFLAGS="-DDEBUG_PROFILE=1 $CFLAGS"
	./configure $CONFIGURE_FLAGS
	make -j 4 V=1
	# 32b build has some issues to find openssl correctly
	if [ "$1" == "valgrind" ]; then
		set +e
		make check-valgrind-memcheck
		RV=$?
		if [ $RV -ne 0 ]; then
			./.github/dump-logs.sh
			exit $RV
		fi
		set -e
	elif [ "$1" != "ix86" ]; then
		set +e
		make check
		RV=$?
		if [ $RV -ne 0 ]; then
			./.github/dump-logs.sh
			exit $RV
		fi
		set -e
	fi
fi

# this is broken in old ubuntu
if [ "$1" == "dist" -o "$2" == "dist" ]; then
	set +e
	DISTCHECK_CONFIGURE_FLAGS="$CONFIGURE_FLAGS"
	make distcheck
	RV=$?
	if [ $RV -ne 0 ]; then
		./.github/dump-logs.sh $SUFFIX
		exit $RV
	fi
	set -e
	make dist
fi

$SUDO make install
if [ "$1" == "mingw" -o "$1" == "mingw32" ]; then
	# pack installed files
	wine "C:/Program Files/Inno Setup 5/ISCC.exe" win32/OpenSC.iss
fi
