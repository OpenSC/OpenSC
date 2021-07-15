#!/bin/bash

if [ ! -d "vsmartcard" ]; then
	git clone https://github.com/frankmorgner/vsmartcard.git
fi
pushd vsmartcard/virtualsmartcard
autoreconf -vis && ./configure && make -j2 && sudo make install
popd
