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
GENERATE_KEYS=1
PKCS11_TOOL="../../tools/pkcs11-tool";
PKCS15_INIT="env OPENSC_CONF=p11test_opensc.conf ../../tools/pkcs15-init"
SC_HSM_TOOL="../../tools/sc-hsm-tool";

function generate_sym() {
	TYPE="$1"
	ID="$2"
	LABEL="$3"

	# Generate key
	$PKCS11_TOOL --keygen --key-type="$TYPE" --login --pin=$PIN \
		--extractable --usage-wrap --usage-decrypt \
		--module="$P11LIB" --label="$LABEL" --id=$ID

	if [[ "$?" -ne "0" ]]; then
		echo "Couldn't generate $TYPE key pair"
		return 1
	fi

	p11tool --login --provider="$P11LIB" --list-all
}

function generate_cert() {
	TYPE="$1"
	ID="$2"
	LABEL="$3"
	CERT="$4" # whether to generate certificate too

	# Generate key pair
	$PKCS11_TOOL --keypairgen --key-type="$TYPE" --login --pin=$PIN \
		--extractable --usage-wrap --usage-sign --usage-decrypt --usage-derive \
		--module="$P11LIB" --label="$LABEL" --id=$ID

	if [[ "$?" -ne "0" ]]; then
		echo "Couldn't generate $TYPE key pair"
		return 1
	fi

	# We can not do this with EdDSA keys as they are not supported in certtool
	# We can not do this with curve25519 keys as they do not need to support signatures at all
	if [[ "$CERT" -ne 0 ]]; then
		# check type value for the PKCS#11 URI (RHEL7 is using old "object-type")
		TYPE_KEY="type"
		export GNUTLS_PIN=$PIN
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
	fi

	p11tool --login --provider="$P11LIB" --list-all
}

function card_setup() {
	ECC_KEYS=1
	EDDSA=1
	SECRET=1
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
			EDDSA=0
			SECRET=0
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
		"kryoptic")
			PIN="$SOPIN"
			P11LIB="/home/jjelen/devel/kryoptic/target/debug/libkryoptic_pkcs11.so"
			KRYOPTIC_DB="kryoptic.sql"
			export KRYOPTIC_CONF="$KRYOPTIC_DB:1"
			# Init token
			$PKCS11_TOOL --init-token --so-pin="$SOPIN" --label="Kryoptic token" --module="$P11LIB"
			$PKCS11_TOOL --init-pin --pin="$PIN" --so-pin="$SOPIN" --label="Kryoptic token" --module="$P11LIB"
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
		"myeid")
			GENERATE_KEYS=0 # we generate them directly here
			P11LIB="../../pkcs11/.libs/opensc-pkcs11.so"
			$PKCS15_INIT --erase-card
			$PKCS15_INIT -C --pin $PIN --puk $SOPIN --so-pin $SOPIN --so-puk $SOPIN
			$PKCS15_INIT -P -a 1 -l "Basic PIN" --pin $PIN --puk $PIN
			INIT="$PKCS15_INIT --auth-id 01 --so-pin $SOPIN --pin $PIN"
			$INIT --generate-key ec:prime256v1 --id 01 --label="EC key" --key-usage=sign,keyAgreement
			$INIT --generate-key rsa:2048 --id 02 --label="RSA key" --key-usage=sign,decrypt
			$INIT --store-secret-key /dev/urandom --secret-key-algorithm aes:256 --extractable --id 03 --label="AES256 key" --key-usage=sign,decrypt
			$INIT --store-secret-key /dev/urandom --secret-key-algorithm aes:128 --extractable --id 04 --label="AES128 key" --key-usage=sign,decrypt
			$PKCS15_INIT -F
			;;
		"sc-hsm")
			GENERATE_KEYS=0 # we generate them directly here
			SOPIN="3537363231383830"
			PIN="648219"
			P11LIB="../../pkcs11/.libs/opensc-pkcs11.so"
			$SC_HSM_TOOL --initialize --so-pin $SOPIN --pin $PIN
			$PKCS11_TOOL --module $P11LIB -l --pin $PIN --keypairgen --key-type rsa:2048 --id 10 --label="RSA key"
			$PKCS11_TOOL --module $P11LIB -l --pin $PIN --keypairgen --key-type EC:prime256v1 --label "EC key"
			;;
		"epass2003")
			GENERATE_KEYS=0 # we generate them directly here
			P11LIB="../../pkcs11/.libs/opensc-pkcs11.so"
			PIN="987654"
			SOPIN="1234567890"
			$PKCS15_INIT --erase-card -T
			$PKCS15_INIT --create-pkcs15 -T -p pkcs15+onepin --pin $PIN --puk 1234567890
			INIT="$PKCS15_INIT --auth-id 01 --so-pin $SOPIN --pin $PIN"
			$INIT --generate-key ec:prime256v1 --id 01 --label="EC key" --key-usage=sign,keyAgreement
			$INIT --generate-key rsa:2048 --id 02 --label="RSA key" --key-usage=sign,decrypt
			$PKCS15_INIT -F
			;;
		*)
			echo "Error: Missing argument."
			echo "    Usage:"
			echo "        runtest.sh [softhsm|opencryptoki|myeid|sc-hsm|kryoptic|readonly [pkcs-library.so]]"
			exit 1;
			;;
	esac

	if [[ $GENERATE_KEYS -eq 1 ]]; then
		# Generate 1024b RSA Key pair
		generate_cert "RSA:1024" "01" "RSA_auth" 1
		# Generate 2048b RSA Key pair
		generate_cert "RSA:2048" "02" "RSA2048" 1
		# Generate 3082b RSA Key pair
		generate_cert "RSA:3072" "09" "RSA3072" 1
		# Generate 4096 RSA Key pair
		generate_cert "RSA:4096" "10" "RSA4096" 1
		if [[ $ECC_KEYS -eq 1 ]]; then
			# Generate 256b ECC Key pair
			generate_cert "EC:secp256r1" "03" "ECC_auth" 1
			# Generate 521b ECC Key pair
			generate_cert "EC:secp521r1" "04" "ECC521" 1
		fi
		if [[ $EDDSA -eq 1 ]]; then
			# Generate Ed25519
			generate_cert "EC:edwards25519" "05" "EDDSA" 0
			# Generate curve25519
			#generate_cert "EC:curve25519" "06" "Curve25519" 0
			# not supported by softhsm either
		fi
		if [[ $SECRET -eq 1 ]]; then
			# Generate AES 128 key
			generate_sym "aes:16" "07" "AES128 key"
			# Generate AES 256 key
			generate_sym "aes:32" "08" "AES256 key"
		fi
	fi
}

function card_cleanup() {
	case $1 in
		"softhsm")
			rm .softhsm2.conf
			rm -rf ".tokens"
			;;
		"kryoptic")
			rm kryoptic.sql
			;;
	esac
}

card_setup "$@"
make p11test || exit
if [[ "$PKCS11SPY" != "" ]]; then
	export PKCS11SPY="$P11LIB"
	$VALGRIND ./p11test -v -m ../../pkcs11/.libs/pkcs11-spy.so -p $PIN &> /tmp/spy.log
	echo "Output stored in /tmp/spy.log"
else
	$VALGRIND ./p11test -v -m "$P11LIB" -o test.json -p $PIN
fi

card_cleanup "$@"
