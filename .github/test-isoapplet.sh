#!/bin/bash

set -ex -o xtrace

source .github/setup-valgrind.sh

isoapplet_version="$1"
if [ "$isoapplet_version" = "v0" ]; then
	isoapplet_branch="main-javacard-v2.2.2"
elif [ "$isoapplet_version" = "v1" ]; then
	isoapplet_branch="main"
else
	echo "Unknown IsoApplet version: $isoapplet_version"
	exit 1
fi

isoapplet_pkgdir="xyz/wendland/javacard/pki/isoapplet"

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# setup java stuff
./.github/setup-java.sh

# The ISO applet
if [ ! -d IsoApplet ]; then
	git clone https://github.com/philipWendland/IsoApplet.git --branch $isoapplet_branch --depth 1
	# enable IsoApplet key import patch
	sed "s/DEF_PRIVATE_KEY_IMPORT_ALLOWED = false/DEF_PRIVATE_KEY_IMPORT_ALLOWED = true/g" -i "IsoApplet/src/${isoapplet_pkgdir}/IsoApplet.java"
fi
javac -classpath jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar IsoApplet/src/${isoapplet_pkgdir}/*.java
echo "com.licel.jcardsim.card.applet.0.AID=F276A288BCFBA69D34F31001" > isoapplet_jcardsim.cfg
echo "com.licel.jcardsim.card.applet.0.Class=${isoapplet_pkgdir//\//.}.IsoApplet" >> isoapplet_jcardsim.cfg
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
$VALGRIND pkcs11-tool -L | tee opensc.log
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

$VALGRIND opensc-tool --card-driver default --send-apdu 80b800001a0cf276a288bcfba69d34f310010cf276a288bcfba69d34f3100100
$VALGRIND opensc-tool -n
$VALGRIND pkcs15-init --create-pkcs15 --so-pin 123456 --so-puk 0123456789abcdef
$VALGRIND pkcs15-tool --change-pin --pin 123456 --new-pin 654321
$VALGRIND pkcs15-tool --unblock-pin --puk 0123456789abcdef --new-pin 123456
$VALGRIND pkcs15-init --generate-key rsa/2048     --id 1 --key-usage decrypt,sign --auth-id FF --pin 123456
$VALGRIND pkcs15-init --generate-key rsa/2048     --id 2 --key-usage decrypt      --auth-id FF --pin 123456
$VALGRIND pkcs15-init --generate-key ec/secp256r1 --id 3 --key-usage sign         --auth-id FF --pin 123456
$VALGRIND pkcs15-tool -D
$VALGRIND pkcs11-tool -l -t -p 123456

# run the tests
pushd src/tests/p11test/
sleep 5
$VALGRIND ./p11test -s 0 -p 123456 -o isoapplet.json
popd

# random data to be signed
dd if=/dev/random of=/tmp/data.bin bs=300 count=1
# sign & verify using secp256r1 key
$VALGRIND pkcs11-tool -l -p 123456 -s -m ECDSA-SHA1 -d 3 -i /tmp/data.bin -o /tmp/data.sig
$VALGRIND pkcs11-tool --verify -m ECDSA-SHA1 -d 3 -i /tmp/data.bin --signature-file /tmp/data.sig
# import, sign & verify using another secp256r1 key
openssl ecparam -name secp256r1 -genkey -noout -out /tmp/ECprivKey.pem
openssl ec -in /tmp/ECprivKey.pem -pubout -out /tmp/ECpubKey.pem
$VALGRIND pkcs11-tool -l -p 123456 -w /tmp/ECprivKey.pem -y privkey -d 4
$VALGRIND pkcs11-tool -l -p 123456 -w /tmp/ECpubKey.pem -y pubkey -d 4
$VALGRIND pkcs11-tool -l -p 123456 -s -m ECDSA-SHA1 -d 4 -i /tmp/data.bin -o /tmp/data.sig
$VALGRIND pkcs11-tool --verify -m ECDSA-SHA1 -d 4 -i /tmp/data.bin --signature-file /tmp/data.sig
# cleanup
rm /tmp/ECprivKey.pem /tmp/ECpubKey.pem /tmp/data.bin /tmp/data.sig

kill -9 $PID

if ! diff -u3 src/tests/p11test/isoapplet_ref_${isoapplet_version}.json src/tests/p11test/isoapplet.json; then
	echo "The output of p11test has changed (see diff above). If that is expected, update the reference file. Otherwise, fix the error."
	exit 1
fi
