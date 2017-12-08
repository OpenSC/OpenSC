#!/bin/bash
# runtest.sh: Run test on existing card with possible initialization
#
# Copyright (C) 2016, 2017 Red Hat, Inc.
#
# Author: Jakub Jelen <jjelen@redhat.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#set -x
SOPIN="12345678"
PIN="123456"
export GNUTLS_PIN=$PIN 
GENERATE_KEYS=1
PKCS11_TOOL="../../tools/pkcs11-tool";

function generate_cert() {
	TYPE="$1"
	ID="$2"
	LABEL="$3"

	# Generate key pair
	$PKCS11_TOOL --keypairgen --key-type="$TYPE" --login --pin=$PIN \
		--module="$P11LIB" --label="$LABEL" --id=$ID

	if [[ "$?" -ne "0" ]]; then
		echo "Couldn't generate $TYPE key pair"
		return 1
	fi

	# check type value for the PKCS#11 URI (RHEL7 is using old "object-type")
	TYPE_KEY="type"
	p11tool --list-all --provider="$P11LIB" --login | grep "object-type" && \
		TYPE_KEY="object-type"

	# Generate certificate
	certtool --generate-self-signed --outfile="$TYPE.cert" --template=cert.cfg \
		--provider="$P11LIB" --load-privkey "pkcs11:object=$LABEL;$TYPE_KEY=private" \
		--load-pubkey "pkcs11:object=$LABEL;$TYPE_KEY=public"
	# convert to DER:
	openssl x509 -inform PEM -outform DER -in "$TYPE.cert" -out "$TYPE.cert.der"
	# Write certificate
	#p11tool --login --write --load-certificate="$TYPE.cert" --label="$LABEL" \
	#	--provider="$P11LIB"
	$PKCS11_TOOL --write-object "$TYPE.cert.der" --type=cert --id=$ID \
		--label="$LABEL" --module="$P11LIB"

	rm "$TYPE.cert" "$TYPE.cert.der"

	p11tool --login --provider="$P11LIB" --list-all
}

function card_setup() {
		ECC_KEYS=1
		case $1 in
			"softhsm")
				P11LIB="/usr/lib64/pkcs11/libsofthsm2.so"
				echo "directories.tokendir = .tokens/" > .softhsm2.conf
				mkdir ".tokens"
				export SOFTHSM2_CONF=".softhsm2.conf"
				# Init token
				softhsm2-util --init-token --slot 0 --label "SC test" --so-pin="$SOPIN" --pin="$PIN"
				;;
			"opencryptoki")
				# Supports only RSA mechanisms
				ECC_KEYS=0
				P11LIB="/usr/lib64/pkcs11/libopencryptoki.so"
				SO_PIN=87654321
				SLOT_ID=3 # swtok slot
				systemctl is-active pkcsslotd > /dev/null
				if [[ "$?" -ne "0" ]]; then
					echo "Opencryptoki needs pkcsslotd running"
					exit 1
				fi
				groups | grep pkcs11 > /dev/null
				if [[ "$?" -ne "0" ]]; then
					echo "Opencryptoki requires the user to be in pkcs11 group"
					exit 1
				fi
				echo "test_swtok" | /usr/sbin/pkcsconf -I -c $SLOT_ID -S $SO_PIN
				/usr/sbin/pkcsconf -u -c $SLOT_ID -S $SO_PIN -n $PIN
				;;
			"readonly")
				GENERATE_KEYS=0
				if [[ ! -z "$2" && -f "$2" ]]; then
					P11LIB="$2"
				else
					P11LIB="/usr/lib64/pkcs11/opensc-pkcs11.so"
					P11LIB="../pkcs11/.libs/opensc-pkcs11.so"
				fi
				;;
			*)
				echo "Error: Missing argument."
				echo "    Usage:"
				echo "        runtest.sh [softhsm|opencryptoki|readonly [pkcs-library.so]]"
				exit 1;
				;;
		esac

		if [[ $GENERATE_KEYS -eq 1 ]]; then
			# Generate 1024b RSA Key pair
			generate_cert "RSA:1024" "01" "RSA_auth"
			# Generate 2048b RSA Key pair
			generate_cert "RSA:2048" "02" "RSA2048"
			if [[ $ECC_KEYS -eq 1 ]]; then
				# Generate 256b ECC Key pair
				generate_cert "EC:secp256r1" "03" "ECC_auth"
				# Generate 521b ECC Key pair
				generate_cert "EC:secp521r1" "04" "ECC521"
			fi
		fi
}

function card_cleanup() {
		case $1 in
			"softhsm")
				rm .softhsm2.conf
				rm -rf ".tokens"
				;;
		esac
}

card_setup "$@"

make p11test || exit
if [[ "$PKCS11SPY" -ne "" ]]; then
	export PKCS11SPY="$P11LIB"
	$VALGRIND ./p11test -m /usr/lib64/pkcs11/pkcs11-spy.so -p $PIN
else
	#bash
	$VALGRIND ./p11test -m "$P11LIB" -o test.json -p $PIN
fi

card_cleanup "$@"
