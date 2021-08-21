#!/bin/bash
set -x
if [ ! -d "vsmartcard" ]; then
	git clone https://github.com/frankmorgner/vsmartcard.git
fi
pushd vsmartcard/virtualsmartcard
git checkout -b  tag-0.8 virtualsmartcard-0.8
autoreconf -vis && ./configure && make -j2 && sudo make install
popd
