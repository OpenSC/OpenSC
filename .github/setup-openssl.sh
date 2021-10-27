#!/bin/bash

set -ex -o xtrace

sudo apt-get remove -y openssl libssl-dev java8-runtime-headless default-jre-headless

if [ ! -d "openssl" ]; then
	git clone https://github.com/openssl/openssl
fi
pushd openssl
git checkout openssl-3.0
./Configure --prefix=/usr/local linux-x86_64
make -j $(nproc)
sudo make install
popd

# update dynamic linker to find the libraries in non-standard path
echo "/usr/local/lib64" | sudo tee /etc/ld.so.conf.d/openssl.conf
sudo ldconfig
