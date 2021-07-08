#!/bin/bash -e

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# setup java stuff
./.github/setup-java.sh

# The ISO applet
git clone https://github.com/philipWendland/IsoApplet.git;
javac -classpath jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar IsoApplet/src/net/pwendland/javacard/pki/isoapplet/*.java;
echo "com.licel.jcardsim.card.applet.0.AID=F276A288BCFBA69D34F31001" > isoapplet_jcardsim.cfg;
echo "com.licel.jcardsim.card.applet.0.Class=net.pwendland.javacard.pki.isoapplet.IsoApplet" >> isoapplet_jcardsim.cfg;
echo "com.licel.jcardsim.card.ATR=3B80800101" >> isoapplet_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.host=localhost" >> isoapplet_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.port=35963" >> isoapplet_jcardsim.cfg;

# log errors from pcscd to console
sudo systemctl stop pcscd.service pcscd.socket
sudo /usr/sbin/pcscd -f &
PCSCD_PID=$!

# start the applet and run couple of commands against that
java -noverify -cp IsoApplet/src/:jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar com.licel.jcardsim.remote.VSmartCard isoapplet_jcardsim.cfg >/dev/null &
PID=$!;
sleep 5;
opensc-tool --card-driver default --send-apdu 80b800001a0cf276a288bcfba69d34f310010cf276a288bcfba69d34f3100100;
opensc-tool -n;
pkcs15-init --create-pkcs15 --so-pin 123456 --so-puk 0123456789abcdef;
pkcs15-tool --change-pin --pin 123456 --new-pin 654321;
pkcs15-tool --unblock-pin --puk 0123456789abcdef --new-pin 123456;
pkcs15-init --generate-key rsa/2048     --id 1 --key-usage decrypt,sign --auth-id FF --pin 123456;
pkcs15-init --generate-key rsa/2048     --id 2 --key-usage decrypt      --auth-id FF --pin 123456;
pkcs15-init --generate-key ec/secp256r1 --id 3 --key-usage sign         --auth-id FF --pin 123456;
pkcs15-tool -D;
pkcs11-tool -l -t -p 123456;
kill -9 $PID;

# cleanup
sudo kill -9 $PCSCD_PID
