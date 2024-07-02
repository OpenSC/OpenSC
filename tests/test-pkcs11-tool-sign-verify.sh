#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

source $SOURCE_PATH/tests/common.sh

echo "======================================================="
echo "Setup SoftHSM"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNING: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi
card_setup
assert $? "Failed to set up card"

# get informaation about OS
source /etc/os-release || true

echo "======================================================="
echo "Test RSA keys"
echo "======================================================="
for HASH in "" "SHA1" "SHA224" "SHA256" "SHA384" "SHA512"; do
    RETOSSL="0"

    if [[ "$ID" == "rhel" || "$ID_LIKE" =~ ".*rhel.*" ]] && [[ "$VERSION" -gt 8 ]] && [[ "$HASH" == "SHA1" ]]; then
        RETOSSL="1"
    fi
    for SIGN_KEY in "01" "02"; do
        METHOD="RSA-PKCS"
        # RSA-PKCS works only on small data - generate small data:
        head -c 64 </dev/urandom > data
        if [[ ! -z $HASH ]]; then
            METHOD="$HASH-$METHOD"
            # hash- methods should work on data > 512 bytes
            head -c 1024 </dev/urandom > data
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
            # pkeyutl does not work with libressl
            #openssl pkeyutl -verify -inkey $SIGN_KEY.pub -in data -sigfile data.sig -pubin
        else
            openssl dgst -keyform PEM -verify $SIGN_KEY.pub -${HASH,,*} \
                   -signature data.sig data
        fi
        if [[ "$RETOSSL" == "0" ]]; then
            assert $? "Failed to Verify signature using OpenSSL"
        elif [[ "$?" == "0" ]]; then
            assert 1 "Unexpectedly Verified signature using OpenSSL"
        fi

        # pkcs11-tool verification
        $PKCS11_TOOL --id $SIGN_KEY --verify -m $METHOD --module $P11LIB \
               --input-file data --signature-file data.sig
        assert $? "Failed to Verify signature using pkcs11-tool"
        rm data.sig

        METHOD="$METHOD-PSS"
        # -PSS methods should work on data > 512 bytes; generate data:
        head -c 1024 </dev/urandom > data
        if [[ "$HASH" == "SHA512" ]]; then
            continue; # This one is broken
        fi

        # Ubuntu SoftHSM version does not support RSA-PSS
        grep "Ubuntu 18.04" /etc/issue && echo "WARNING: Not supported on Ubuntu 18.04" && continue

        echo
        echo "======================================================="
        echo "$METHOD: Sign & Verify (KEY $SIGN_KEY)"
        echo "======================================================="
        if [[ -z $HASH ]]; then
            # hashing is done outside of the module. We choose here SHA256
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
        if [[ "$RETOSSL" == "0" ]]; then
            assert $? "Failed to Verify signature using openssl"
        elif [[ "$?" == "0" ]]; then
            assert 1 "Unexpectedly Verified signature using OpenSSL"
        fi

        # pkcs11-tool verification
        $PKCS11_TOOL --id $SIGN_KEY --verify -m $METHOD --module $P11LIB \
               $HASH_ALGORITM --salt-len=-1 \
               --input-file data.hash --signature-file data.sig
        assert $? "Failed to Verify signature using pkcs11-tool"
        rm data.{sig,hash}
    done

    METHOD="RSA-PKCS-OAEP"
    # RSA-PKCS-OAEP works only on small data (input length <= k-2-2hLen)
    # generate small data:
    head -c 64 </dev/urandom > data
    for ENC_KEY in "01" "02"; do
        # SoftHSM only supports SHA1 for both hashAlg and mgf
        if [[ -z $HASH ]]; then
        	continue
        elif [[ "$HASH" != "SHA1" ]]; then
        	continue
        fi
        echo
        echo "======================================================="
        echo "$METHOD: Encrypt & Decrypt (KEY $ENC_KEY)"
        echo "======================================================="
        # OpenSSL Encryption
        # pkeyutl does not work with libressl
        openssl rsautl -encrypt -oaep -inkey $ENC_KEY.pub -in data -pubin -out data.crypt
        assert $? "Failed to encrypt data using OpenSSL"
        $PKCS11_TOOL --id $ENC_KEY --decrypt -p $PIN --module $P11LIB \
               -m $METHOD --hash-algorithm "SHA-1" --mgf "MGF1-SHA1" \
               --input-file data.crypt --output-file data.decrypted
        assert $? "Failed to decrypt data using pkcs11-tool"
        diff data{,.decrypted}
        assert $? "The decrypted data do not match the original"
        rm data.{crypt,decrypted}

        $PKCS11_TOOL --id $ENC_KEY --encrypt -p $PIN --module $P11LIB \
               -m $METHOD --hash-algorithm "SHA-1" --mgf "MGF1-SHA1" \
               --input-file data --output-file data.crypt
        assert $? "Failed to encrypt data using pkcs11-tool"
        # It would be better to decrypt with OpenSSL but we can't read the
        # private key with the pkcs11-tool (yet)
        $PKCS11_TOOL --id $ENC_KEY --decrypt -p $PIN --module $P11LIB \
               -m $METHOD --hash-algorithm "SHA-1" --mgf "MGF1-SHA1" \
               --input-file data.crypt --output-file data.decrypted
        assert $? "Failed to decrypt data using pkcs11-tool"
        diff data{,.decrypted}
        assert $? "The decrypted data do not match the original"
        rm data.{crypt,decrypted}
    done

    # Skip hashed algorithms (do not support encryption & decryption)
    if [[ ! -z "$HASH" ]]; then
        continue;
    fi
    METHOD="RSA-PKCS"
    # RSA-PKCS works only on small data - generate small data:
    head -c 64 </dev/urandom > data
    for ENC_KEY in "01" "02"; do
        echo
        echo "======================================================="
        echo "$METHOD: Encrypt & Decrypt (KEY $ENC_KEY)"
        echo "======================================================="
        # OpenSSL Encryption
        openssl rsautl -encrypt -inkey $ENC_KEY.pub -in data \
               -pubin -out data.crypt
        # pkeyutl does not work with libressl
        #openssl pkeyutl -encrypt -inkey $ENC_KEY.pub -in data \
        #       -pubin -out data.crypt
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
echo "Test ECDSA keys"
echo "======================================================="
# operations with ECDSA keys should work on data > 512 bytes; generate data:
head -c 1024 </dev/urandom > data
for SIGN_KEY in "03" "04"; do
    METHOD="ECDSA"

    echo
    echo "======================================================="
    echo "$METHOD: Sign & Verify (KEY $SIGN_KEY)"
    echo "======================================================="
    openssl dgst -binary -sha256 data > data.hash
    $PKCS11_TOOL --id $SIGN_KEY -s -p $PIN -m $METHOD --module $P11LIB \
        --input-file data.hash --output-file data.sig
    assert $? "Failed to Sign data"
    $PKCS11_TOOL --id $SIGN_KEY -s -p $PIN -m $METHOD --module $P11LIB \
        --input-file data.hash --output-file data.sig.openssl \
        --signature-format openssl
    assert $? "Failed to Sign data into OpenSSL format"

    # OpenSSL verification
    openssl dgst -keyform PEM -verify $SIGN_KEY.pub -sha256 \
               -signature data.sig.openssl data
    assert $? "Failed to Verify signature using OpenSSL"

    # pkcs11-tool verification
    $PKCS11_TOOL --id $SIGN_KEY --verify -m $METHOD --module $P11LIB \
           --input-file data.hash --signature-file data.sig
    assert $? "Failed to Verify signature using pkcs11-tool"
    rm data.sig{,.openssl} data.hash
done

echo "======================================================="
echo "Test GENERIC keys"
echo "======================================================="

echo "Hello World" > data.msg

for MECHANISM in "SHA-1-HMAC" "SHA256-HMAC" "SHA384-HMAC" "SHA512-HMAC"; do
	echo
	echo "======================================================="
	echo "$MECHANISM: Sign & Verify (KEY (First Found))"
	echo "======================================================="

	$PKCS11_TOOL --login --pin=$PIN --sign --mechanism=$MECHANISM \
		--input-file=data.msg --output-file=data.sig --module $P11LIB
	assert $? "Failed to Sign data"
	$PKCS11_TOOL --login --pin=$PIN --verify --mechanism=$MECHANISM \
		--input-file=data.msg --signature-file=data.sig --module $P11LIB
	assert $? "Failed to Verify signature using pkcs11-tool"
	rm data.sig
done;

rm data.msg

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

rm data

exit $ERRORS
