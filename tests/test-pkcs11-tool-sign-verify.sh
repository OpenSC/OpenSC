## from OpenSC/src/tests/p11test/runtest.sh
SOPIN="12345678"
PIN="123456"
PKCS11_TOOL="../src/tools/pkcs11-tool"
P11LIB="/usr/lib64/pkcs11/libsofthsm2.so"

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

	# convert it to more digestible PEM format
	if [[ ${TYPE:0:3} == "RSA" ]]; then
		openssl rsa -inform DER -outform PEM -in $ID.der -pubin > $ID.pub
	else
		openssl ec -inform DER -outform PEM -in $ID.der -pubin > $ID.pub
	fi
	rm $ID.der
}

function card_setup() {
	echo "directories.tokendir = .tokens/" > .softhsm2.conf
	mkdir ".tokens"
	export SOFTHSM2_CONF=".softhsm2.conf"
	# Init token
	softhsm2-util --init-token --slot 0 --label "SC test" --so-pin="$SOPIN" --pin="$PIN"

	# Generate 1024b RSA Key pair
	generate_key "RSA:1024" "01" "RSA_auth"
	# Generate 2048b RSA Key pair
	generate_key "RSA:2048" "02" "RSA2048"
	# Generate 256b ECC Key pair
	# generate_key "EC:secp256r1" "03" "ECC_auth"
	# Generate 521b ECC Key pair
	# generate_key "EC:secp521r1" "04" "ECC521"
	# TODO ECDSA keys tests
}

function card_cleanup() {
	rm .softhsm2.conf
	rm -rf ".tokens"
	rm 0{1,2}.pub
}

echo "======================================================="
echo "Setup SoftHSM"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNINIG: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi
card_setup
echo "data to sign (max 100 bytes)" > data

for HASH in "" "SHA1" "SHA224" "SHA256" "SHA384" "SHA512"; do
    for SIGN_KEY in "01" "02"; do
        METHOD="RSA-PKCS"
        if [[ ! -z $HASH ]]; then
            METHOD="$HASH-$METHOD"
        fi
        echo
        echo "======================================================="
        echo "$METHOD: Sign & Verify (KEY $SIGN_KEY)"
        echo "======================================================="
        $PKCS11_TOOL --id $SIGN_KEY -s -p $PIN -m $METHOD --module $P11LIB \
               --input-file data --output-file data.sig
        assert $? "Failed to Sign data"

        # OpenSSL verification
        if [[ -z $HASH ]]; then
            openssl rsautl -verify -inkey $SIGN_KEY.pub -in data.sig -pubin
        else
            openssl dgst -keyform PEM -verify $SIGN_KEY.pub -${HASH,,*} \
                   -signature data.sig data
        fi
        assert $? "Failed to Verify signature using OpenSSL"

        # pkcs11-tool verification
        $PKCS11_TOOL --id $SIGN_KEY --verify -m $METHOD --module $P11LIB \
               --input-file data --signature-file data.sig
        assert $? "Failed to Verify signature using pkcs11-tool"
        rm data.sig

        METHOD="$METHOD-PSS"
        if [[ "$HASH" == "SHA512" ]]; then
            continue; # This one is broken
        fi

        echo
        echo "======================================================="
        echo "$METHOD: Sign & Verify (KEY $SIGN_KEY)"
        echo "======================================================="
        if [[ -z $HASH ]]; then
            # hashing is done outside of the module. We chouse here SHA256
            openssl dgst -binary -sha256 data > data.hash
            HASH_ALGORITM="--hash-algorithm=SHA256"
            VERIFY_DGEST="-sha256"
            VERIFY_OPTS="-sigopt rsa_mgf1_md:sha256"
        else
            # hashing is done inside of the module
            cp data data.hash
            HASH_ALGORITM=""
            VERIFY_DGEST="-${HASH,,*}"
            VERIFY_OPTS="-sigopt rsa_mgf1_md:${HASH,,*}"
        fi
        $PKCS11_TOOL --id $SIGN_KEY -s -p $PIN -m $METHOD --module $P11LIB \
               $HASH_ALGORITM --salt-len=-1 \
               --input-file data.hash --output-file data.sig
        assert $? "Failed to Sign data"

        # OpenSSL verification
        openssl dgst -keyform PEM -verify $SIGN_KEY.pub $VERIFY_DGEST \
               -sigopt rsa_padding_mode:pss  $VERIFY_OPTS -sigopt rsa_pss_saltlen:-1 \
               -signature data.sig data
        assert $? "Failed to Verify signature using openssl"

        # pkcs11-tool verification
        $PKCS11_TOOL --id $SIGN_KEY --verify -m $METHOD --module $P11LIB \
               $HASH_ALGORITM --salt-len=-1 \
               --input-file data.hash --signature-file data.sig
        assert $? "Failed to Verify signature using pkcs11-tool"
        rm data.{sig,hash}
    done

    # Skip hashed algorithms (do not support encryption & decryption)
    if [[ ! -z "$HASH" ]]; then
        continue;
    fi
    METHOD="RSA-PKCS"
    for ENC_KEY in "01" "02"; do
        echo
        echo "======================================================="
        echo "$METHOD: Encrypt & Decrypt (KEY $ENC_KEY)"
        echo "======================================================="
        # OpenSSL Encryption
        openssl rsautl -encrypt -inkey $ENC_KEY.pub -in data \
               -pubin -out data.crypt
        assert $? "Failed to encrypt data using OpenSSL"
        $PKCS11_TOOL --id $ENC_KEY --decrypt -p $PIN -m $METHOD \
               --module $P11LIB --input-file data.crypt > data.decrypted
        diff data{,.decrypted}
        assert $? "The decrypted data do not match the original"
        rm data.{crypt,decrypted}

        # TODO pkcs11-tool encryption not supported
    done
done

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit $ERRORS
