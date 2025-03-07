#!/bin/bash
## from OpenSC/src/tests/p11test/runtest.sh
BUILD_PATH=${BUILD_PATH:-..}

TOKENTYPE=$1

# run valgrind with all the switches we are interested in
if [ -n "$VALGRIND" -a -n "$LOG_COMPILER" ]; then
    VALGRIND="$LOG_COMPILER"
fi

export SOPIN="12345678"
export PIN="123456"
PKCS11_TOOL="$VALGRIND $BUILD_PATH/src/tools/pkcs11-tool"

if [ "${TOKENTYPE}" == "softhsm" ]; then
    source "${BUILD_PATH}/tests/setup-softhsm.sh"
elif [ "${TOKENTYPE}" == "softokn" ]; then
    source "${BUILD_PATH}/tests/setup-softokn.sh"
elif [ "${TOKENTYPE}" == "kryoptic" ]; then
    source "${BUILD_PATH}/tests/setup-kryoptic.sh"
else
    echo "Unknown token type: $1"
    exit 1
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
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --keypairgen --key-type="$TYPE" --label="$LABEL" --id=$ID
	if [[ "$?" -ne "0" ]]; then
		echo "Couldn't generate $TYPE key pair"
		return 1
	fi

	# Extract public key from the card
	$PKCS11_TOOL "${PUB_ARGS[@]}" --read-object --id $ID --type pubkey --output-file $ID.der
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

function card_setup() {
	initialize_token

	# Generate 2048b RSA Key pair
	generate_key "RSA:2048" "01" "RSA2048" || return 1
	# Generate 4096b RSA Key pair
	generate_key "RSA:4096" "02" "RSA4096" || return 1
	# Generate 256b ECC Key pair
	generate_key "EC:secp256r1" "03" "ECC_auth" || return 1
	# Generate 521b ECC Key pair
	generate_key "EC:secp521r1" "04" "ECC521" || return 1

	if [[ ${TOKENTYPE} == "softhsm" ]]; then
		# Generate an HMAC:SHA256 key
		$PKCS11_TOOL --keygen --key-type="GENERIC:64" --login --pin=$PIN \
			--module="$P11LIB" --label="HMAC-SHA256" --id="05"
		if [[ "$?" -ne "0" ]]; then
			echo "Couldn't generate GENERIC key"
			return 1
		fi
	fi
}

function card_cleanup() {
	token_cleanup
	rm 0{1,2,3,4}.pub
	sleep 1
}
