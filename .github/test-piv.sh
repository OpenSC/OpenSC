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


# prepare pcscd
. .github/restart-pcscd.sh


# start the applet and run couple of commands against that
java -noverify -cp PivApplet/bin/:jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar com.licel.jcardsim.remote.VSmartCard PivApplet/test/jcardsim.cfg >/dev/null &
PID=$!
sleep 5

$VALGRIND opensc-tool --card-driver default --send-apdu 80b80000120ba000000308000010000100050000020F0F7f
$VALGRIND opensc-tool -n

PIN="123456"
echo '01:02:03:04:05:06:07:08:01:02:03:04:05:06:07:08' > key
export PIV_EXT_AUTH_KEY="$(pwd)/key"

#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9e -a generate -A RSA2048 | tee 9e.pub
#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9e -S'/CN=barCard/OU=test/O=example.com/' -averify-pin -aselfsign < 9e.pub | tee 9e.cert
#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9e -aimport-certificate < 9e.cert
$VALGRIND piv-tool -v -A M:9B:07 -G 9E:07 -o 9e.pub
export PIV_9E_KEY="$(pwd)/9e.pub"
openssl req -key "pkcs11:id=%04;type=private;pin-value=$PIN" -subj "/CN=barCard/OU=test/O=example.com/" -new -x509 -out 9e.cert
$VALGRIND piv-tool -v -A M:9B:07 -C 9E -i 9e.cert

#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9a -a generate -A RSA2048 | tee 9a.pub
#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9a -S'/CN=bar/OU=test/O=example.com/' -averify-pin -aselfsign < 9a.pub | tee 9a.cert
#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9a -aimport-certificate < 9a.cert
$VALGRIND piv-tool -v -A M:9B:07 -G 9A:07 -o 9a.pub
export PIV_9A_KEY="$(pwd)/9a.pub"
openssl req -key "pkcs11:id=%01;type=private;pin-value=$PIN" -subj "/CN=bar/OU=test/O=example.com/" -new -x509 -out 9a.cert
$VALGRIND piv-tool -v -A M:9B:07 -C 9A -i 9a.cert

#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9c -a generate -A ECCP256 | tee 9c.pub
#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9c -S'/CN=bar/OU=test/O=example.com/' -averify-pin -aselfsign < 9c.pub | tee 9c.cert
#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9c -aimport-certificate < 9c.cert
$VALGRIND piv-tool -v -A M:9B:07 -G 9C:11 -o 9c.pub
export PIV_9C_KEY="$(pwd)/9c.pub"
openssl req -key "pkcs11:id=%02;type=private;pin-value=$PIN" -subj "/CN=bar/OU=test/O=example.com/" -new -x509 -out 9c.cert
$VALGRIND piv-tool -v -A M:9B:07 -C 9C -i 9c.cert

#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9d -a generate -A ECCP256 | tee 9d.pub
#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9d -S'/CN=bar/OU=test/O=example.com/' -averify-pin -aselfsign < 9d.pub | tee 9d.cert
#yubico-piv-tool -v 9999 -r 'Virtual PCD 00 00' -P "$PIN" -s 9d -aimport-certificate < 9d.cert
$VALGRIND piv-tool -v -A M:9B:07 -G 9D:11 -o 9d.pub
export PIV_9D_KEY="$(pwd)/9d.pub"
openssl req -key "pkcs11:id=%03;type=private;pin-value=$PIN" -subj "/CN=bar/OU=test/O=example.com/" -new -x509 -out 9d.cert
$VALGRIND piv-tool -v -A M:9B:07 -C 9D -i 9d.cert

$VALGRIND pkcs11-tool -l -O -p "$PIN"
$VALGRIND pkcs11-tool -l -t -p "$PIN"

# run p11test
pushd src/tests/p11test/
sleep 5
$VALGRIND ./p11test -v -s 0 -p "$PIN" -o piv.json
popd
diff -u3 src/tests/p11test/piv{_ref,}.json 

kill -9 $PID
