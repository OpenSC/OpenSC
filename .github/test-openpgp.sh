#!/bin/bash -e

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# setup java stuff
. .github/setup-java.sh

# The OpenPGP applet
git clone --recursive https://github.com/Yubico/ykneo-openpgp.git;
cd ykneo-openpgp;
ant -DJAVACARD_HOME=${JC_HOME};
cd $TRAVIS_BUILD_DIR;
echo "com.licel.jcardsim.card.applet.0.AID=D2760001240102000000000000010000" > openpgp_jcardsim.cfg;
echo "com.licel.jcardsim.card.applet.0.Class=openpgpcard.OpenPGPApplet" >> openpgp_jcardsim.cfg;
echo "com.licel.jcardsim.card.ATR=3B80800101" >> openpgp_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.host=localhost" >> openpgp_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.port=35963" >> openpgp_jcardsim.cfg;

# log errors from pcscd to console
sudo systemctl stop pcscd.service pcscd.socket
sudo /usr/sbin/pcscd -f &
PCSCD_PID=$!


# start the applet and run couple of commands against that
java -noverify -cp ykneo-openpgp/applet/bin:jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar com.licel.jcardsim.remote.VSmartCard openpgp_jcardsim.cfg >/dev/null &
PID=$!;
sleep 5;
opensc-tool --card-driver default --send-apdu 80b800002210D276000124010200000000000001000010D276000124010200000000000001000000;
opensc-tool -n;
openpgp-tool --verify CHV3 --pin 12345678 --gen-key 2;
pkcs15-init --verify --auth-id 3 --pin 12345678 --delete-objects privkey,pubkey --id 2 --generate-key rsa/2048;
pkcs11-tool -l -t -p 123456;
kill -9 $PID


# cleanup
sudo kill -9 $PCSCD_PID
