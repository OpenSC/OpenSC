#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

function compare_keys() {
    RET=$1
    EXTRACTED=$2
    PLAIN=$3

    if [ $RET == 0 ]; then
        cmp $EXTRACTED $PLAIN >/dev/null 2>/dev/null
        assert $? "Extracted key does not match the input key"
    else
        # softokn and kryoptic keys are extractable but sensitive
        echo "Key cannot be read in plaintext"
    fi
}

function test_unwrapped_aes_encryption() {
    AES_256_KEY=$1
    KEY_ID=$2
    IV="00000000000000000000000000000000"
    (printf '\xAB%.0s' {1..64};) > aes_plain.data

    echo "Testing unwrapped key with encryption"

    # Encrypt with openssl
    openssl enc -aes-256-cbc -in aes_plain.data -out aes_ciphertext_openssl.data -iv $IV -K $AES_256_KEY
    assert $? "AES CBC OpenSSL encryption failed"

    # Encrypt with pkcs11-tool
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --encrypt --id $KEY_ID -m AES-CBC-PAD --iv $IV \
            --input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data
    assert $? "Fail/pkcs11-tool encrypt"

    # Compare ciphertexts
    cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
    assert $? "AES CBC encrypted ciphertexts do not match"

    rm aes_ciphertext_openssl.data aes_ciphertext_pkcs11.data aes_plain.data
}

TOKENTYPE=$1

if [ "${TOKENTYPE}" == "" ]; then
    TOKENTYPE=softhsm
    echo "No tokentype provided, running with SoftHSM"
fi

source $SOURCE_PATH/tests/common.sh $TOKENTYPE

echo "======================================================="
echo "Setup $TOKENTYPE"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNING: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi

initialize_token

# create AES key
AES_256_KEY="7070707070707070707070707070707070707070707070707070707070707070"
echo -n $AES_256_KEY | xxd -p -r > aes.key

echo "======================================================="
echo " RSA Wrap/Unwrap tests"
echo "======================================================="
ID_RSA_WRAP="85" # RSA wrapping key
ID_GENERIC_UNWRAPPED_1="95" # GENERIC key
ID_AES_UNWRAPPED_1="96" # AES key

# Generate RSA key for unwrap/wrap operation
$PKCS11_TOOL "${PRIV_ARGS[@]}" --keypairgen --key-type rsa:1024 --id $ID_RSA_WRAP --usage-wrap --usage-decrypt --label rsa-wrapping-key
assert $? "Failed to Generate RSA key"

# Export public key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --read-object --type pubkey --id $ID_RSA_WRAP -o rsa_pub.key
assert $? "Failed to export public key"

echo "======================================================="
echo " RSA-PKCS Unwrap generic key test"
echo "======================================================="

# Wrap with OpenSSL
openssl rsautl -encrypt -pubin -keyform der -inkey rsa_pub.key -in aes.key -out openssl_wrapped.data
assert $? "OpenSSL failed wrap AES key"

# Unwrap with pkcs11-tool as generic key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m RSA-PKCS --id $ID_RSA_WRAP -i openssl_wrapped.data --key-type GENERIC: \
	--application-id $ID_GENERIC_UNWRAPPED_1 --application-label "unwrap-generic-ex-with-rsa-pkcs" --extractable 2>/dev/null
assert $? "RSA-PKCS unwrap GENERIC key failed"

# Compare original and unwrapped key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ID_GENERIC_UNWRAPPED_1 --read-object --type secrkey --output-file generic_extracted.key
compare_keys $? generic_extracted.key aes.key

echo "======================================================="
echo " RSA-PKCS Unwrap AES key test"
echo "======================================================="

# Unwrap with pkcs11-tool as AES key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m RSA-PKCS --id $ID_RSA_WRAP -i openssl_wrapped.data --key-type AES: \
	--application-id $ID_AES_UNWRAPPED_1  --application-label "unwrap-aes-with-rsa-pkcs" --extractable 2>/dev/null
assert $? "RSA-PKCS unwrap AES key failed"

# Read value of unwrapped key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ID_AES_UNWRAPPED_1 --read-object --type secrkey --output-file aes_extracted.key

# Compare original and unwrapped key
compare_keys $? aes_extracted.key aes.key

# Check if AES key was correctly unwrapped with encryption
test_unwrapped_aes_encryption $AES_256_KEY $ID_AES_UNWRAPPED_1

echo "======================================================="
echo " RSA-PKCS Wrap AES key test"
echo "======================================================="

# Wrap with pkcs11-tool
$PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m RSA-PKCS --id $ID_RSA_WRAP --application-id $ID_AES_UNWRAPPED_1 --output-file pkcs11_wrapped.data
assert $? "Unable to wrap with RSA-PKCS"

# Compare keys with decryption
$PKCS11_TOOL "${PRIV_ARGS[@]}" --decrypt -m RSA-PKCS --id $ID_RSA_WRAP --input-file pkcs11_wrapped.data --output-file aes_wrapped_decrypted.key
assert $? "Unable to decrypt wrapped key"
cmp aes_wrapped_decrypted.key aes.key >/dev/null 2>/dev/null
assert $? "Wrapped key after decipher does not match the original key"

rm openssl_wrapped.data generic_extracted.key pkcs11_wrapped.data aes_wrapped_decrypted.key aes_extracted.key

if [ "${TOKENTYPE}" != "softokn" ]; then
    echo "======================================================="
    echo " RSA-PKCS-OAEP Unwrap generic key test"
    echo "======================================================="
    # RSA-PKCS-OAEP mechanism takes both a hash algorithm and MGF algorithm as parameters.
    # For now we use SHA1, although it has been deprecated by NIST, because SoftHSM only supports SHA1 hash with OAEP currently.
    # Known issue: https://github.com/softhsm/SoftHSMv2/issues/474 . When this issue is fixed, we shall replace with SHA256 or higher.

    OSSL_OAEP_HASH_ALG="sha1"
    P11_OAEP_HASH_ALG="SHA-1"
    P11_OAEP_MGF_ALG="MGF1-SHA1"

    # Identifiers (pkcs11-tool --application-id argument) of PKCS11 key objects to be created
    ID_GENERIC_UNWRAPPED_2="97"
    ID_AES_UNWRAPPED_3="98"

    # Wrap with OpenSSL
    openssl pkeyutl -encrypt -pubin -keyform DER -inkey rsa_pub.key -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:$OSSL_OAEP_HASH_ALG -pkeyopt rsa_mgf1_md:$OSSL_OAEP_HASH_ALG -in aes.key -out openssl_wrapped.data
    assert $? "OpenSSL failed wrap AES key"

    # Unwrap with pkcs11-tool as generic key
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m RSA-PKCS-OAEP --hash-algorithm $P11_OAEP_HASH_ALG --mgf $P11_OAEP_MGF_ALG --id $ID_RSA_WRAP -i openssl_wrapped.data --key-type GENERIC: \
        --extractable --application-id $ID_GENERIC_UNWRAPPED_2 --application-label "unwrap-aes-ex-with-rsa-oaep" 2>/dev/null
    assert $? "RSA-PKCS-OAEP unwrap GENERIC key failed"

    # Compare original and unwrapped key
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ID_GENERIC_UNWRAPPED_2 --read-object --type secrkey --output-file generic_extracted.key
    compare_keys $? generic_extracted.key aes.key

    echo "======================================================="
    echo " RSA-PKCS-OAEP Unwrap AES key test"
    echo "======================================================="

    # Unwrap with pkcs11-tool as AES key
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m RSA-PKCS-OAEP --hash-algorithm $P11_OAEP_HASH_ALG --mgf $P11_OAEP_MGF_ALG --id $ID_RSA_WRAP -i openssl_wrapped.data --key-type AES: \
        --extractable --application-id $ID_AES_UNWRAPPED_3 --application-label "unwrap-aes-non-ex-with-rsa-oaep" 2>/dev/null
    assert $? "RSA-PKCS-OAEP unwrap AES key failed"

    # Compare original and unwrapped key
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ID_AES_UNWRAPPED_1 --read-object --type secrkey --output-file aes_extracted.key
    compare_keys $? aes_extracted.key aes.key

    # Check if AES key was correctly unwrapped with encryption
    test_unwrapped_aes_encryption $AES_256_KEY $ID_AES_UNWRAPPED_3

    echo "======================================================="
    echo " RSA-PKCS-OAEP Wrap test"
    echo "======================================================="

    # Wrap with pkcs11-tool
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m RSA-PKCS-OAEP --id $ID_RSA_WRAP --hash-algorithm $P11_OAEP_HASH_ALG --mgf $P11_OAEP_MGF_ALG --application-id $ID_GENERIC_UNWRAPPED_2 --output-file pkcs11_wrapped.data
    assert $? "Unable to wrap with RSA-PKCS-OAEP"

    # Compare keys with decryption
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --decrypt -m RSA-PKCS-OAEP --hash-algorithm $P11_OAEP_HASH_ALG --mgf $P11_OAEP_MGF_ALG --id $ID_RSA_WRAP --input-file pkcs11_wrapped.data --output-file aes_wrapped_decrypted.key
    assert $? "Fail, unable to decrypt wrapped key"
    cmp aes_wrapped_decrypted.key aes.key >/dev/null 2>/dev/null
    assert $? "Wrapped key after decipher does not match the original key"

    rm  openssl_wrapped.data generic_extracted.key pkcs11_wrapped.data aes_wrapped_decrypted.key aes_extracted.key

fi

rm rsa_pub.key

echo "======================================================="
echo " AES Wrap/Unwrap tests"
echo "======================================================="
ID_AES_WRAP="0101" # AES wrapping key
ID_AES_UNWRAPPED_4="0102" # AES 256 CBC
ID_AES_UNWRAPPED_5="0103" # AES-KEY-WRAP
ID_AES_UNWRAPPED_6="0104" # AES-KEY-WRAP-PAD

is_openssl_3=$(openssl version | grep "OpenSSL 3.")
is_softhsm2_2_6_1=$(softhsm2-util -version | grep "2.6.1")

# Generate AES key for unwrap/wrap operation
AES_WRAP=$(head /dev/urandom | sha256sum | head -c 64)
echo -n $AES_WRAP | xxd -p -r > aes_kek.key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --write-object aes_kek.key --id $ID_AES_WRAP --type secrkey \
    --key-type AES:32 --usage-wrap --extractable --label aes-32-wrapping-key
assert $? "Failed to write AES key"

if [[ "$TOKENTYPE" != "softhsm" || -n "$is_softhsm2_2_6_1" ]]; then
    # CKM_AES_CBC -- SoftHSM2 AES CBC wrapping currently has a bug, the IV is not correctly used. Only IV=0 will work --*
    IV="00000000000000000000000000000000"

    echo "======================================================="
    echo " AES 256 CBC Unwrap test"
    echo "======================================================="
    # Wrap with OpenSSL
    openssl enc -aes-256-cbc -e -K $AES_WRAP -iv $IV -in aes.key -out openssl_wrapped.data -nopad
    assert $? "OpenSSL / Failed to AES CBC encrypt AES key"

    if [ "${TOKENTYPE}" == "softhsm" ]; then
        echo "SoftHSM2 currently does not support CKM_AES_CBC unwrapping"
        # SoftHSM does not have the wrapped key already, write it for the wrap test
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --write-object aes.key --id $ID_AES_UNWRAPPED_4 --type secrkey --key-type AES:32 \
            --usage-decrypt --extractable --label "stored-aes-32-cbc"
        assert $? "PKCS11 / Failed to write AES key"
    else
        # Unwrap with pkcs11-tool
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m AES-CBC --id $ID_AES_WRAP --iv $IV --application-id $ID_AES_UNWRAPPED_4 \
            --key-type AES: --input-file openssl_wrapped.data --extractable --application-label "unwrap-aes-with-aes-32-cbc"
        assert $? "PKCS11 / Failed to AES CBC unwrap AES key"

        # Compare original and unwrapped key
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --read-object --type secrkey --id $ID_AES_UNWRAPPED_4 --output-file unwrapped.key
        compare_keys $? aes.key unwrapped.key

        # Check if AES key was correctly unwrapped with encryption
        test_unwrapped_aes_encryption $AES_256_KEY $ID_AES_UNWRAPPED_4
    fi
    echo "======================================================="
    echo " AES 256 CBC Wrap test"
    echo "======================================================="
    # Wrap with OpenSSL
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m AES-CBC --id $ID_AES_WRAP --iv $IV --application-id $ID_AES_UNWRAPPED_4 \
        --output-file pkcs11_wrapped.data
    assert $? "Fail, unable to wrap"

    # Compare OpenSSL and pkcs11-tool wrapped keys
    cmp pkcs11_wrapped.data openssl_wrapped.data >/dev/null 2>/dev/null
    assert $? "Fail, AES-CBC - wrapped key incorrect"
else
    echo "Not supported"
fi

if [[ "$TOKENTYPE" != "softhsm" ]]; then
    # SoftHSM2 currently doesn't support CKM_AES_CBC_PAD as a wrapping
    echo "======================================================="
    echo " AES 256 CBC PAD Wrap test"
    echo "======================================================="
    IV="000102030405060708090A0B0C0D0E0F"
    # Wrap with OpenSSL
    openssl enc -aes-256-cbc -e -K $AES_WRAP -iv $IV -in aes.key -out openssl_wrapped.data
    assert $? "OpenSSL / Failed to AES CBC encrypt AES key"

    # Wrap with pkcs11-tool
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m AES-CBC-PAD --id $ID_AES_WRAP --iv $IV --application-id $ID_AES_UNWRAPPED_4 --output-file pkcs11_wrapped.data
    assert $? "PKCS11 / Failed to AES CBC PAD wrap AES key"

    # Compare OpenSSL and pkcs11-tool wrapped keys
    cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
    assert $?  "AES 256 CBC PAD wrapped keys do not match"
fi

if [[ -n $is_openssl_3 ]]; then
    echo "======================================================="
    echo "AES-KEY-WRAP Wrap test"
    echo "======================================================="
    # RSA Key
    # --AES-KEY-WRAP is not suitable for asymmetric key wrapping since the length of the encoded private key is likely not aligned to 8 bytes
    IV="a6a6a6a6a6a6a6a6"

    # Wrap with OpenSSL
    openssl enc -id-aes256-wrap -e -K $AES_WRAP -iv $IV -in aes.key -out openssl_wrapped.data
    assert $? "OpenSSL / Failed to AES KEY WRAP wrap AES key"
    
    # Wrap with pkcs11-tool
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m AES-KEY-WRAP --id $ID_AES_WRAP --iv $IV --application-id $ID_AES_UNWRAPPED_4 \
        --output-file pkcs11_wrapped.data
    assert $? "PKCS11 / Failed to AES KEY WRAP wrap AES key"

    # Compare OpenSSL and pkcs11-tool wrapped keys
    cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
    assert $? "AES-KEY-WRAP wrapped keys do not match"

    echo "======================================================="
    echo "AES-KEY-WRAP Unwrap test"
    echo "======================================================="
    # Unwrap with pkcs11-tool
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m AES-KEY-WRAP --id $ID_AES_WRAP --iv $IV --application-id $ID_AES_UNWRAPPED_5 \
        --key-type AES: --input-file pkcs11_wrapped.data --extractable --application-label "unwrap-aes-with-aes-key-wrap"
    assert $? "PKCS11 / Failed to AES KEY WRAP wrap unwrap AES key"

    # Read value of unwrapped key
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --read-object --type secrkey --id $ID_AES_UNWRAPPED_5 --output-file unwrapped.key

    # Compare original and unwrapped key
    compare_keys $? aes.key unwrapped.key

    # Check if AES key was correctly unwrapped with encryption
    test_unwrapped_aes_encryption $AES_256_KEY $ID_AES_UNWRAPPED_4

    if [[ "$TOKENTYPE" != "kryoptic" ]]; then
        echo "======================================================="
        echo "AES-KEY-WRAP-PAD Wrap test"
        echo "======================================================="
        IV="a65959a6"

        # Wrap with OpenSSL
        openssl enc -aes256-wrap-pad -e -K $AES_WRAP -iv $IV -in aes.key -out openssl_wrapped.data
        assert $? "OpenSSL failed wrap AES key"

        # Wrap with pkcs11-tool
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m AES-KEY-WRAP-PAD --id $ID_AES_WRAP --iv $IV \
                --application-id $ID_AES_UNWRAPPED_4 --output-file pkcs11_wrapped.data
        assert $? "PKCS11 / Failed to AES KEY WRAP PAD wrap AES key"

        # Compare OpenSSL and pkcs11-tool wrapped keys
        if [[ "$TOKENTYPE" != "softokn" ]]; then
            cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
            assert $? "AES-KEY-WRAP-PAD wrapped keys do not match"
        else
            echo "Comparing OpenSSL and pkcs11-tool wrapped keys for softokn fails"
        fi

        echo "======================================================="
        echo "AES-KEY-WRAP-PAD Unwrap test"
        echo "======================================================="
        # Unwrap with pkcs11-tool
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m AES-KEY-WRAP-PAD --id $ID_AES_WRAP --iv $IV --application-id $ID_AES_UNWRAPPED_6 \
                --key-type AES: --input-file pkcs11_wrapped.data --extractable --application-label "unwrap-aes-with-aes-key-wrap-pad"
        assert $? "PKCS11 / Failed to AES KEY WRAP PAD wrap unwrap AES key"

        # Read value of unwrapped key
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --read-object --type secrkey --id $ID_AES_UNWRAPPED_6 --output-file unwrapped.key

        # Compare original and unwrapped key
        compare_keys $? aes.key unwrapped.key
        
        # Check if AES key was correctly unwrapped with encryption
        test_unwrapped_aes_encryption $AES_256_KEY $ID_AES_UNWRAPPED_4
    fi
fi

rm -f aes.key aes_kek.key pkcs11_wrapped.data openssl_wrapped.data unwrapped.key

echo "======================================================="
echo "Cleanup"
echo "======================================================="
token_cleanup

exit $ERRORS
