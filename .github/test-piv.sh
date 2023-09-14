#!/bin/bash

set -ex -o xtrace

source .github/setup-valgrind.sh

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
	pushd yubico-piv-tool
	if [ ! -d "build" ]; then
		mkdir build
		pushd build
		cmake .. && make
		popd
	fi
	popd
fi
pushd yubico-piv-tool/build
	sudo make install
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/x86_64-linux-gnu
popd


# prepare pcscd
. .github/restart-pcscd.sh


# start the applet and run couple of commands against that
java -noverify -cp PivApplet/bin/:jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar com.licel.jcardsim.remote.VSmartCard PivApplet/test/jcardsim.cfg >/dev/null &
PID=$!
sleep 5

# enforce the setting of different PIV type to support EC mechanisms
# which are disabled for the generic ATR mapping to older Yubico devices
export OPENSC_CONF="${PWD}/.github/opensc-piv.conf"

$VALGRIND opensc-tool --card-driver default --send-apdu 80b80000120ba000000308000010000100050000020F0F7f
$VALGRIND opensc-tool -n

PIN="123456"
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9e -a generate -A RSA2048 | tee 9e.pub
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9e -S'/CN=barCard/OU=test/O=example.com/' -averify -aselfsign < 9e.pub | tee 9e.cert
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9e -aimport-certificate < 9e.cert

yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9a -a generate -A RSA2048 | tee 9a.pub
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9a -S'/CN=bar/OU=test/O=example.com/' -averify -aselfsign < 9a.pub | tee 9a.cert
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9a -aimport-certificate < 9a.cert

yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9c -a generate -A ECCP256 | tee 9c.pub
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9c -S'/CN=bar/OU=test/O=example.com/' -averify -aselfsign < 9c.pub | tee 9c.cert
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9c -aimport-certificate < 9c.cert

yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9d -a generate -A ECCP256 | tee 9d.pub
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9d -S'/CN=bar/OU=test/O=example.com/' -averify -aselfsign < 9d.pub | tee 9d.cert
yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9d -aimport-certificate < 9d.cert

$VALGRIND pkcs11-tool -l -O -p "$PIN"
$VALGRIND pkcs11-tool -l -t -p "$PIN"

# run p11test
pushd src/tests/p11test/
sleep 5
$VALGRIND ./p11test -v -s 0 -p "$PIN" -o piv.json
popd
diff -u3 src/tests/p11test/piv{_ref,}.json

kill -9 $PID
