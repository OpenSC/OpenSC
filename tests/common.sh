#!/bin/bash
## from OpenSC/src/tests/p11test/runtest.sh
BUILD_PATH=${BUILD_PATH:-..}

# run valgrind with all the switches we are interested in
if [ -n "$VALGRIND" -a -n "$LOG_COMPILER" ]; then
    VALGRIND="$LOG_COMPILER"
fi

SOPIN="12345678"
PIN="123456"
PKCS11_TOOL="$VALGRIND $BUILD_PATH/src/tools/pkcs11-tool"

softhsm_paths="/usr/local/lib/softhsm/libsofthsm2.so \
	/usr/lib/softhsm/libsofthsm2.so
	/usr/lib64/pkcs11/libsofthsm2.so \
	/usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so \
	/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"

for LIB in $softhsm_paths; do
	echo "Testing $LIB"
	if [[ -f $LIB ]]; then
		P11LIB=$LIB
		echo "Setting P11LIB=$LIB"
		break
	fi
done
if [[ -z "$P11LIB" ]]; then
	echo "Warning: Could not find the softhsm pkcs11 module"
fi

ERRORS=0
function assert() {
	if [[ $1 != 0 ]]; then
		echo "====> ERROR: $2"
		ERRORS=1
	fi
}

function generate_key() {
	TYPE="$1"
	ID="$2"
	LABEL="$3"

	echo "Generate $TYPE key (ID=$ID)"
	# Generate key pair
	$PKCS11_TOOL --keypairgen --key-type="$TYPE" --login --pin=$PIN \
		--module="$P11LIB" --label="$LABEL" --id=$ID
	if [[ "$?" -ne "0" ]]; then
		echo "Couldn't generate $TYPE key pair"
		return 1
	fi

	# Extract public key from the card
	$PKCS11_TOOL --read-object --id $ID --type pubkey --output-file $ID.der \
		--module="$P11LIB"
	if [[ "$?" -ne "0" ]]; then
		echo "Couldn't read generated $TYPE public key"
		return 1
	fi

	# convert it to more digestible PEM format
	if [[ ${TYPE:0:3} == "RSA" ]]; then
		openssl rsa -inform DER -outform PEM -in $ID.der -pubin > $ID.pub
	elif [[ $TYPE == "EC:edwards25519" ]]; then
		openssl pkey -inform DER -outform PEM -in $ID.der -pubin > $ID.pub
	else
		openssl ec -inform DER -outform PEM -in $ID.der -pubin > $ID.pub
	fi
	rm $ID.der
}

function softhsm_initialize() {
	echo "directories.tokendir = $(realpath .tokens)" > .softhsm2.conf
	if [ -d ".tokens" ]; then
		rm -rf ".tokens"
	fi
	mkdir ".tokens"
	export SOFTHSM2_CONF=$(realpath ".softhsm2.conf")
	# Init token
	softhsm2-util --init-token --slot 0 --label "SC test" --so-pin="$SOPIN" --pin="$PIN"
}

function card_setup() {
	softhsm_initialize

	# Generate 1024b RSA Key pair
	generate_key "RSA:1024" "01" "RSA_auth" || return 1
	# Generate 2048b RSA Key pair
	generate_key "RSA:2048" "02" "RSA2048" || return 1
	# Generate 256b ECC Key pair
	generate_key "EC:secp256r1" "03" "ECC_auth" || return 1
	# Generate 521b ECC Key pair
	generate_key "EC:secp521r1" "04" "ECC521" || return 1
	# Generate an HMAC:SHA256 key
	$PKCS11_TOOL --keygen --key-type="GENERIC:64" --login --pin=$PIN \
		--module="$P11LIB" --label="HMAC-SHA256" --id="05"
	if [[ "$?" -ne "0" ]]; then
		echo "Couldn't generate GENERIC key"
		return 1
	fi
}

function softhsm_cleanup() {
	rm .softhsm2.conf
	rm -rf ".tokens"
}

function card_cleanup() {
	softhsm_cleanup
	rm 0{1,2,3,4}.pub
}
