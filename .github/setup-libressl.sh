#!/bin/bash

set -ex -o xtrace

V=libressl-3.4.2

sudo apt-get remove -y openssl libssl-dev java8-runtime-headless default-jre-headless

if [ ! -d "$V" ]; then
	# letsencrypt CA does not seem to be included in CI runner
	wget --no-check-certificate https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/$V.tar.gz
	tar xzf $V.tar.gz
fi
pushd $V
./configure --prefix=/usr/local
make -j $(nproc)
sudo make install
popd

# update dynamic linker to find the libraries in non-standard path
echo "/usr/local/lib64" | sudo tee /etc/ld.so.conf.d/openssl.conf
sudo ldconfig
