#!/bin/bash

set -ex -o xtrace

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# setup java stuff and virutal smartcard
. .github/setup-java.sh

# The PIV Applet
if [ ! -d "PivApplet" ]; then
	git clone --recursive https://github.com/arekinath/PivApplet.git
fi
pushd PivApplet
JC_HOME=${JC_CLASSIC_HOME} ant dist
popd

# yubico-piv-tool is needed for PIV Applet management 
if [ ! -d "yubico-piv-tool" ]; then
	git clone https://github.com/Yubico/yubico-piv-tool.git
fi
pushd yubico-piv-tool
if [ ! -d "build" ]; then
	mkdir build
fi
pushd build
cmake .. && make && sudo make install
popd
popd


# prepare pcscd
. .github/restart-pcscd.sh


# start the applet and run couple of commands against that
java -noverify -cp PivApplet/bin/:jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar com.licel.jcardsim.remote.VSmartCard PivApplet/test/jcardsim.cfg >/dev/null &
PID=$!
sleep 5
opensc-tool --card-driver default --send-apdu 80b80000120ba000000308000010000100050000020F0F7f
opensc-tool -n

yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P 123456 -s 9e -a generate -A RSA2048 | tee 9e.pub
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P 123456 -s 9e -S'/CN=barCard/OU=test/O=example.com/' -averify -aselfsign < 9e.pub | tee 9e.cert
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P 123456 -s 9e -aimport-certificate <9e.cert

yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P 123456 -s 9a -a generate -A ECCP256 | tee 9a.pub
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P 123456 -s 9a -S'/CN=bar/OU=test/O=example.com/' -averify -aselfsign < 9a.pub | tee 9e.cert
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P 123456 -s 9a -aimport-certificate < 9e.cert

pkcs11-tool -l -O -p 123456
pkcs11-tool -l -t -p 123456
kill -9 $PID
