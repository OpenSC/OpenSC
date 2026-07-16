#!/bin/bash

set -ex -o xtrace

source .github/setup-valgrind.sh

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# vsmartcard
./.github/setup-vsmartcard.sh

if [ ! -d pico-hsm ]; then
	git clone --depth 1 --branch v6.6 https://github.com/polhenarejos/pico-hsm.git
	git -C pico-hsm submodule update --init --recursive
fi
if [ ! -d pico-hsm/build ]; then
	mkdir pico-hsm/build
	cmake -DENABLE_EMULATION=1 -S pico-hsm -B pico-hsm/build
fi
if [ ! -f pico-hsm/build/pico_hsm ]; then
	make -C pico-hsm/build
fi

# prepare pcscd
#PCSCD_DEBUG="-d -a"
. .github/restart-pcscd.sh

sleep 2
rm -f memory.flash
tar -xf pico-hsm/tests/memory.tar.gz
pico-hsm/build/pico_hsm &
PID=$!
sleep 2

# run the tests
pushd src/tests/p11test/
sleep 5
$VALGRIND sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 648219
$VALGRIND ./p11test -s 0 -p 648219 -o pico-hsm.json
diff -u3 pico-hsm_ref.json pico-hsm.json
popd

# cleanup -- this would break later uses of pcscd
kill -9 $PID
