#!/bin/bash

set -ex -o xtrace

if [ ! -d "vsmartcard" ]; then
	git clone https://github.com/frankmorgner/vsmartcard.git
	pushd vsmartcard/virtualsmartcard
	autoreconf -vis && ./configure && make -j2
	popd
fi
pushd vsmartcard/virtualsmartcard
sudo make install
popd
