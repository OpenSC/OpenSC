#!/bin/bash

set -ex -o xtrace

uname -a

source .github/setup-valgrind.sh

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# setup java stuff
. .github/setup-java.sh

# The OpenPGP applet
if [ ! -d "ykneo-openpgp" ]; then
	git clone --recursive https://github.com/Yubico/ykneo-openpgp.git;
fi
pushd ykneo-openpgp;
ant -DJAVACARD_HOME=${JC_HOME};
popd
echo "com.licel.jcardsim.card.applet.0.AID=D2760001240102000000000000010000" > openpgp_jcardsim.cfg;
echo "com.licel.jcardsim.card.applet.0.Class=openpgpcard.OpenPGPApplet" >> openpgp_jcardsim.cfg;
echo "com.licel.jcardsim.card.ATR=3B80800101" >> openpgp_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.host=localhost" >> openpgp_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.port=35963" >> openpgp_jcardsim.cfg;


# prepare pcscd
PCSCD_DEBUG="-d -a"
. .github/restart-pcscd.sh

sleep 5
echo "Is pcscd running:"
ps -ef | grep  pcscd

echo "Test for /var/run/pcscd/"
if [ -d /var/run/pcscd/ ] ; then
	ls -la /var/run/pcscd/*
	if [ -f /var/run/pcscd/pcscd.pid ] ; then
		echo "/var/run/pcscd/pcscd.pid `cat /var/run/pcscd/pcscd.pid`"
	fi
fi

echo "Test for /run/pcscd/"
if [ -d /run/pcscd/ ] ; then
	ls -la /run/pcscd/*
	if [ -f /run/pcscd/pcscd.pid ] ; then
		echo "/run/pcscd/pcscd.pid `cat /run/pcscd/pcscd.pid`" 
	fi

fi
ps  -ef |  grep pcsc

# start the applet and run couple of commands against that
java -noverify -cp ykneo-openpgp/applet/bin:jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar com.licel.jcardsim.remote.VSmartCard openpgp_jcardsim.cfg >/dev/null &
PID=$!;
echo java pid $PID
sleep 5;
$VALGRIND opensc-tool --card-driver default --send-apdu 80b800002210D276000124010200000000000001000010D276000124010200000000000001000000;
$VALGRIND opensc-tool -n;
$VALGRIND openpgp-tool --verify CHV3 --pin 12345678 --gen-key 2;
$VALGRIND pkcs15-init --verify --auth-id 3 --pin 12345678 --delete-objects privkey,pubkey --id 2 --generate-key rsa/2048;
$VALGRIND pkcs11-tool -l -t -p 123456;

# generate new keys and run p11test
$VALGRIND openpgp-tool --verify CHV3 --pin 12345678 --gen-key 1;
$VALGRIND openpgp-tool --verify CHV3 --pin 12345678 --gen-key 3;
pushd src/tests/p11test/
sleep 5
# signing key 1 is on slot 1
$VALGRIND ./p11test -v -s 0 -p 123456 -o openpgp_s0.json
$VALGRIND ./p11test -v -s 1 -p 123456 -o openpgp_s1.json
popd
diff -u3 src/tests/p11test/openpgp_s0{_ref,}.json
diff -u3 src/tests/p11test/openpgp_s1{_ref,}.json

kill -9 $PID
ps -ef | grep pcsc
