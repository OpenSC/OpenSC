#!/bin/bash -e

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

if [ ! -d oseid ]; then
	git clone https://github.com/popovec/oseid
fi
pushd oseid/src/
make -f Makefile.console
if [ ! -d tmp ]; then
	mkdir tmp
fi
socat -d -d pty,link=tmp/OsEIDsim.socket,raw,echo=0 "exec:build/console/console ...,pty,raw,echo=0" &
PID=$!
sleep 1
echo "# OsEIDsim" > tmp/reader.conf
echo 'FRIENDLYNAME      "OsEIDsim"' >> tmp/reader.conf
echo "DEVICENAME        $PWD/tmp/OsEIDsim.socket" >> tmp/reader.conf
echo "LIBPATH           $PWD/build/console/libOsEIDsim.so.0.0.1" >> tmp/reader.conf
echo "CHANNELID         1" >> tmp/reader.conf
sudo mv tmp/reader.conf /etc/reader.conf.d/reader.conf
cat /etc/reader.conf.d/reader.conf
popd
 
sudo /etc/init.d/pcscd restart

# Needed for tput to not report warnings
export TERM=xterm-256color

pushd oseid/tools
echo | ./OsEID-tool INIT
./OsEID-tool RSA-CREATE-KEYS
./OsEID-tool RSA-UPLOAD-KEYS
./OsEID-tool RSA-DECRYPT-TEST
./OsEID-tool RSA-SIGN-PKCS11-TEST
./OsEID-tool EC-CREATE-KEYS
./OsEID-tool EC-UPLOAD-KEYS
./OsEID-tool EC-SIGN-TEST
./OsEID-tool EC-SIGN-PKCS11-TEST
./OsEID-tool EC-ECDH-TEST
popd

# this does not work as we have random key IDs in here
#pushd src/tests/p11test/
#./p11test -s 0 -p 11111111 -o oseid.json || true
#diff -u3 oseid_ref.json oseid.json
#popd

# cleanup -- this would break later uses of pcscd
kill -9 $PID
rm oseid/src/card_mem
sudo rm /etc/reader.conf.d/reader.conf
