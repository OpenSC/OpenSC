#!/bin/bash

set -ex -o xtrace

# WARNING: Change this also in .github/workflows/linux.yml
V=libressl-4.0.0

sudo apt-get remove -y libssl-dev

if [ ! -d "$V" ]; then
	# letsencrypt CA does not seem to be included in CI runner
	wget --no-check-certificate https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/$V.tar.gz
	tar xzf $V.tar.gz

	pushd $V
	./configure --prefix=/usr/local
	make -j $(nproc)
	popd
fi

pushd $V
sudo make install
popd

# update dynamic linker to find the libraries in non-standard path
echo "/usr/local/lib64" | sudo tee /etc/ld.so.conf.d/openssl.conf
sudo ldconfig
