#!/bin/bash -e

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# setup java stuff
. .github/setup-java.sh

# GidsApplet
git clone https://github.com/vletoux/GidsApplet.git;
javac -classpath jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar GidsApplet/src/com/mysmartlogon/gidsApplet/*.java;
echo "com.licel.jcardsim.card.applet.0.AID=A000000397425446590201" > gids_jcardsim.cfg;
echo "com.licel.jcardsim.card.applet.0.Class=com.mysmartlogon.gidsApplet.GidsApplet" >> gids_jcardsim.cfg;
echo "com.licel.jcardsim.card.ATR=3B80800101" >> gids_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.host=localhost" >> gids_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.port=35963" >> gids_jcardsim.cfg;

# log errors from pcscd to console
sudo systemctl stop pcscd.service pcscd.socket
sudo /usr/sbin/pcscd -f &
PCSCD_PID=$!


# start the applet and run couple of commands against that
java -noverify -cp GidsApplet/src/:jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar com.licel.jcardsim.remote.VSmartCard gids_jcardsim.cfg >/dev/null &
PID=$!;
sleep 5;
opensc-tool --card-driver default --send-apdu 80b80000190bA0000003974254465902010bA00000039742544659020100;
opensc-tool -n;
gids-tool --initialize --pin 123456 --admin-key 000000000000000000000000000000000000000000000000 --serial 00000000000000000000000000000000;
kill -9 $PID


# cleanup
sudo kill -9 $PCSCD_PID
