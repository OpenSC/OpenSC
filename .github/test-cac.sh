#!/bin/bash -e

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# VSmartcard
./.github/setup-vsmartcard.sh

# libcacard
if [ ! -d "libcacard" ]; then
	git clone https://gitlab.freedesktop.org/spice/libcacard.git
fi
pushd libcacard
./autogen.sh --prefix=/usr && make -j2 && sudo make install
popd

# virt_cacard
if [ ! -d "virt_cacard" ]; then
	git clone https://github.com/Jakuje/virt_cacard.git
fi
pushd virt_cacard
./autogen.sh && ./configure && make
popd

sudo /etc/init.d/pcscd restart

pushd src/tests/p11test/
./p11test -s 0 -p 12345678 -i -o virt_cacard.json &
sleep 5
popd

# virt_cacard startup
pushd virt_cacard
./setup-softhsm2.sh
export SOFTHSM2_CONF=$PWD/softhsm2.conf
./virt_cacard &
wait $(ps aux | grep '[p]11test'| awk '{print $2}')
kill -9 $(ps aux | grep '[v]irt_cacard'| awk '{print $2}')
popd

# cleanup -- this would break later uses of pcscd
pushd vsmartcard/virtualsmartcard
sudo make uninstall
popd

diff -u3 src/tests/p11test/virt_cacard{_ref,}.json
