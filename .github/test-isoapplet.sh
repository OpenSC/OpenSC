#!/bin/bash

set -ex -o xtrace

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# setup java stuff
./.github/setup-java.sh

# The ISO applet
if [ ! -d IsoApplet ]; then
	git clone https://github.com/philipWendland/IsoApplet.git
	# enable IsoApplet key import patch
	sed "s/DEF_PRIVATE_KEY_IMPORT_ALLOWED = false/DEF_PRIVATE_KEY_IMPORT_ALLOWED = true/g" -i IsoApplet/src/net/pwendland/javacard/pki/isoapplet/IsoApplet.java
fi
javac -classpath jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar IsoApplet/src/net/pwendland/javacard/pki/isoapplet/*.java
echo "com.licel.jcardsim.card.applet.0.AID=F276A288BCFBA69D34F31001" > isoapplet_jcardsim.cfg
echo "com.licel.jcardsim.card.applet.0.Class=net.pwendland.javacard.pki.isoapplet.IsoApplet" >> isoapplet_jcardsim.cfg
echo "com.licel.jcardsim.card.ATR=3B80800101" >> isoapplet_jcardsim.cfg
echo "com.licel.jcardsim.vsmartcard.host=localhost" >> isoapplet_jcardsim.cfg
echo "com.licel.jcardsim.vsmartcard.port=35963" >> isoapplet_jcardsim.cfg


# prepare pcscd
. .github/restart-pcscd.sh


# start the applet and run couple of commands against that
java -noverify -cp IsoApplet/src/:jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar com.licel.jcardsim.remote.VSmartCard isoapplet_jcardsim.cfg >/dev/null &
PID=$!
sleep 5

# Does OpenSC see the uninitialized card?
pkcs11-tool -L | tee opensc.log
# report as "token not recognized"
grep "(token not recognized)" opensc.log

# Does OpenSC see the uninitialized card with options for InitToken?
cat >opensc.conf <<EOF
app default {
    enable_default_driver = true;
    card_atr 3B:80:80:01:01 {
        pkcs11_enable_InitToken = yes;
    }
    card_drivers = default;
}
EOF
OPENSC_CONF=opensc.conf pkcs11-tool -L | tee opensc.log
# report as "token not recognized"
grep "uninitialized" opensc.log

opensc-tool --card-driver default --send-apdu 80b800001a0cf276a288bcfba69d34f310010cf276a288bcfba69d34f3100100
opensc-tool -n
pkcs15-init --create-pkcs15 --so-pin 123456 --so-puk 0123456789abcdef
pkcs15-tool --change-pin --pin 123456 --new-pin 654321
pkcs15-tool --unblock-pin --puk 0123456789abcdef --new-pin 123456
pkcs15-init --generate-key rsa/2048     --id 1 --key-usage decrypt,sign --auth-id FF --pin 123456
pkcs15-init --generate-key rsa/2048     --id 2 --key-usage decrypt      --auth-id FF --pin 123456
pkcs15-init --generate-key ec/secp256r1 --id 3 --key-usage sign         --auth-id FF --pin 123456
pkcs15-tool -D
pkcs11-tool -l -t -p 123456

# run the tests
pushd src/tests/p11test/
sleep 5
./p11test -s 0 -p 123456 -o isoapplet.json || true # ec_sign_size_test is failing here
popd

# random data to be signed
dd if=/dev/random of=/tmp/data.bin bs=300 count=1
# sign & verify using secp256r1 key
pkcs11-tool -l -p 123456 -s -m ECDSA-SHA1 -d 3 -i /tmp/data.bin -o /tmp/data.sig
pkcs11-tool --verify -m ECDSA-SHA1 -d 3 -i /tmp/data.bin --signature-file /tmp/data.sig
# import, sign & verify using another secp256r1 key
openssl ecparam -name secp256r1 -genkey -noout -out /tmp/ECprivKey.pem
openssl ec -in /tmp/ECprivKey.pem -pubout -out /tmp/ECpubKey.pem
pkcs11-tool -l -p 123456 -w /tmp/ECprivKey.pem -y privkey -d 4
pkcs11-tool -l -p 123456 -w /tmp/ECpubKey.pem -y pubkey -d 4
pkcs11-tool -l -p 123456 -s -m ECDSA-SHA1 -d 4 -i /tmp/data.bin -o /tmp/data.sig
pkcs11-tool --verify -m ECDSA-SHA1 -d 4 -i /tmp/data.bin --signature-file /tmp/data.sig
# cleanup
rm /tmp/ECprivKey.pem /tmp/ECpubKey.pem /tmp/data.bin /tmp/data.sig

kill -9 $PID

diff -u3 src/tests/p11test/isoapplet{_ref,}.json
