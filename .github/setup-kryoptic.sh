#!/bin/bash

# build kryoptic
if [ ! -d "kryoptic" ]; then
	git clone https://github.com/latchset/kryoptic.git
fi
pushd kryoptic
git submodule init
git submodule update
cargo build --features dynamic,standard,nssdb
popd
