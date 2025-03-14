#!/bin/bash

# build kryoptic
if [ ! -d "kryoptic" ]; then
	git clone https://github.com/latchset/kryoptic.git
fi
pushd kryoptic
cargo build --features dynamic,standard,nssdb
popd
