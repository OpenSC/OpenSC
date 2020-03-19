#!/bin/bash

source common.sh

echo "======================================================="
echo "Setup SoftHSM"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNINIG: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi
card_setup
echo "data to sign (max 100 bytes)" > data

echo "======================================================="
echo "Test RSA keys"
echo "======================================================="
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
echo "Test ECDSA keys"
echo "======================================================="
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
echo "Cleanup"
echo "======================================================="
card_cleanup

rm data

exit $ERRORS
