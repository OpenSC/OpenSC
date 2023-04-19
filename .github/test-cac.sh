#!/bin/bash

set -ex -o xtrace

source .github/setup-valgrind.sh

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# VSmartcard
./.github/setup-vsmartcard.sh

# libcacard
if [ ! -d "libcacard" ]; then
	git clone https://gitlab.freedesktop.org/spice/libcacard.git
	pushd libcacard
	./autogen.sh --prefix=/usr && make -j2
	popd
fi
pushd libcacard
sudo make install
popd

# prepare pcscd
. .github/restart-pcscd.sh

# virt_cacard
if [ ! -d "virt_cacard" ]; then
	git clone https://github.com/Jakuje/virt_cacard.git
	pushd virt_cacard
	./autogen.sh && ./configure && make
	popd
fi
pushd virt_cacard
./setup-softhsm2.sh
export SOFTHSM2_CONF=$PWD/softhsm2.conf
./virt_cacard 2>&1 | sed -e 's/^/virt_cacard: /;' &
PID=$!
popd

# run the tests
pushd src/tests/p11test/
sleep 5
$VALGRIND ./p11test -s 0 -p 12345678 -o virt_cacard.json
popd

diff -u3 src/tests/p11test/virt_cacard{_ref,}.json

kill -9 $PID
