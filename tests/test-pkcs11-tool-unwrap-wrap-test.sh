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
        echo "Key cannot be read in plaintext"
    fi
}

TOKENTYPE=$1

if [ "${TOKENTYPE}" == "softokn" ]; then
	echo "Wrap/unwrap test not supported"
	exit 1
elif [ "${TOKENTYPE}" == "" ]; then
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

echo "======================================================="
echo " RSA-PKCS Unwrap test"
echo "======================================================="
ID1="85" # RSA key
ID2="95" # GENERIC key
ID3="96" # AES key
# Generate RSA key (this key is used to unwrap/wrap operation)
$PKCS11_TOOL "${PRIV_ARGS[@]}" --keypairgen --key-type rsa:1024 --id $ID1 --usage-wrap --usage-decrypt --label wrap-rsa
assert $? "Failed to Generate RSA key"

# export public key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --read-object --type pubkey --id $ID1 -o rsa_pub.key
assert $? "Failed to export public key"

# create AES key
KEY="70707070707070707070707070707070"

echo -n $KEY|xxd -p -r > aes_plain_key
# wrap AES key
openssl rsautl -encrypt -pubin -keyform der -inkey rsa_pub.key -in aes_plain_key -out aes_wrapped_key
assert $? "Failed wrap AES key"

# unwrap key as generic key by pkcs11 interface
$PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m RSA-PKCS --id $ID1 -i aes_wrapped_key --key-type GENERIC: \
	--extractable --application-id $ID3 --application-label "unwrap-generic-ex" --extractable 2>/dev/null
assert $? "Unwrap failed"

# if extractable, there is no problem to compare key value with original key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ID3 --read-object --type secrkey --output-file generic_extracted_key
compare_keys $? generic_extracted_key aes_plain_key

# unwrap AES key, not extractable
$PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m RSA-PKCS --id $ID1 -i aes_wrapped_key --key-type AES: \
	--application-id $ID2 --application-label "unwrap-aes" 2>/dev/null
assert $? "Unwrap failed"

# To check if AES key was correctly unwrapped (non extractable), we need to encrypt some data by pkcs11 interface and by openssl
# (with same key). If result is same, key was correctly unwrapped.
VECTOR="00000000000000000000000000000000"
echo -n "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" > aes_plain.data

openssl enc -aes-128-cbc -nopad -in aes_plain.data -out aes_ciphertext_openssl.data -iv $VECTOR -K $KEY
assert $? "Fail/Openssl"

$PKCS11_TOOL "${PRIV_ARGS[@]}" --encrypt --id $ID2 -m AES-CBC --iv $VECTOR \
        --input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC - wrong encrypt"

echo "======================================================="
echo " RSA-PKCS Wrap test"
echo "======================================================="

$PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m RSA-PKCS --id $ID1 --application-id $ID3 --output-file wrapped.key
assert $? "Fail, unable to wrap"

$PKCS11_TOOL "${PRIV_ARGS[@]}" --decrypt -m RSA-PKCS --id $ID1 --input-file wrapped.key --output-file plain_wrapped.key
assert $? "Fail, unable to decrypt wrapped key"
cmp plain_wrapped.key aes_plain_key >/dev/null 2>/dev/null
assert $? "wrapped key after decipher does not match the original key"
echo "RSA-PKCS wrap test successful"

echo "======================================================="
echo " RSA-PKCS-OAEP Unwrap test"
echo "======================================================="
# RSA-PKCS-OAEP mechanism takes both a hash algorithm and MGF algorithm as parameters. For now we use SHA1, although it has been deprecated by NIST, because SoftHSM only supports SHA1 hash with OAEP currently. Known issue: https://github.com/softhsm/SoftHSMv2/issues/474 . When this issue is fixed, we shall replace with SHA256 or higher.
# OpenSSL rsa_oaep_md hash algorithm option
OSSL_OAEP_HASH_ALG="sha1"
# pkcs11-tool hash-algorithm option
P11_OAEP_HASH_ALG="SHA-1"
# pkcs11-tool mgf option
P11_OAEP_MGF_ALG="MGF1-SHA1"

# Identifiers (pkcs11-tool --application-id argument) of PKCS11 key objects to be created
ID4="97"
ID5="98"

# Reusing AES key and RSA key for unwrap/wrap operation already generated with ID1 in previous RSA-PKCS Unwrap test
# Cleanup previously generated output
rm aes_wrapped_key generic_extracted_key aes_ciphertext_openssl.data aes_ciphertext_pkcs11.data wrapped.key plain_wrapped.key

# wrap AES key with RSA OAEP mode 
openssl pkeyutl -encrypt -pubin -keyform DER -inkey rsa_pub.key -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:$OSSL_OAEP_HASH_ALG -pkeyopt rsa_mgf1_md:$OSSL_OAEP_HASH_ALG -in aes_plain_key -out aes_wrapped_key
assert $? "Failed wrap AES key"

# unwrap key by pkcs11 interface, extractable
$PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m RSA-PKCS-OAEP --hash-algorithm $P11_OAEP_HASH_ALG --mgf $P11_OAEP_MGF_ALG --id $ID1 -i aes_wrapped_key --key-type GENERIC: \
	--extractable --application-id $ID4 --application-label "unwrap-aes-ex-with-rsa-oaep" 2>/dev/null
assert $? "Unwrap failed"

# because key is extractable, there is no problem to compare key value with original key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --id $ID4 --read-object --type secrkey --output-file generic_extracted_key
compare_keys $? generic_extracted_key aes_plain_key

# unwrap AES key, not extractable
$PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m RSA-PKCS-OAEP --hash-algorithm $P11_OAEP_HASH_ALG --mgf $P11_OAEP_MGF_ALG --id $ID1 -i aes_wrapped_key --key-type AES: \
	--application-id $ID5 --application-label "unwrap-aes-non-ex-with-rsa-oaep" 2>/dev/null
assert $? "Unwrap failed"

# To check if AES key was correctly unwrapped (non extractable), we do the same as in the RSA-PKCS test.
openssl enc -aes-128-cbc -nopad -in aes_plain.data -out aes_ciphertext_openssl.data -iv $VECTOR -K $KEY
assert $? "Fail/Openssl"

$PKCS11_TOOL "${PRIV_ARGS[@]}" --encrypt --id $ID5 -m AES-CBC --iv $VECTOR \
        --input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC - wrong encrypt"


echo "======================================================="
echo " RSA-PKCS-OAEP Wrap test"
echo "======================================================="

$PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m RSA-PKCS-OAEP --id $ID1 --hash-algorithm $P11_OAEP_HASH_ALG --mgf $P11_OAEP_MGF_ALG --application-id $ID4 --output-file wrapped.key
assert $? "Fail, unable to wrap"

$PKCS11_TOOL "${PRIV_ARGS[@]}" --decrypt -m RSA-PKCS-OAEP --hash-algorithm $P11_OAEP_HASH_ALG --mgf $P11_OAEP_MGF_ALG --id $ID1 --input-file wrapped.key --output-file plain_wrapped.key
assert $? "Fail, unable to decrypt wrapped key"
cmp plain_wrapped.key aes_plain_key >/dev/null 2>/dev/null
assert $? "wrapped key after decipher does not match the original key"
echo "RSA-PKCS-OAEP wrap test successful"

echo "======================================================="
echo " RSA-PKCS / RSA-PKCS-OAEP Cleanup"
echo "======================================================="

rm rsa_pub.key aes_plain_key aes_wrapped_key aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data aes_plain.data generic_extracted_key wrapped.key plain_wrapped.key

echo "======================================================="
echo " AES wrap/unwrap"
echo "======================================================="

is_openssl_3=$(openssl version | grep "OpenSSL 3.")
is_softhsm2_2_6_1=$(softhsm2-util -version | grep "2.6.1")

$PKCS11_TOOL "${PRIV_ARGS[@]}" -O

ID_KEK="0101"
ID_UNWRAPPED="0102"

AES_KEY="7070707070707070707070707070707070707070707070707070707070707070"
echo -n $AES_KEY | xxd -p -r > aes.key

AES_KEK=$(head /dev/urandom | sha256sum | head -c 64)
echo -n $AES_KEK | xxd -p -r > aes_kek.key
$PKCS11_TOOL "${PRIV_ARGS[@]}" --write-object aes_kek.key --id $ID_KEK --type secrkey \
    --key-type AES:32 --usage-wrap --extractable --label wrap-aes-32
assert $? "PKCS11 / Failed to write AES KEK"

if [[ "$TOKENTYPE" != "softhsm" || -n "$is_softhsm2_2_6_1" ]]; then
    # CKM_AES_CBC -- SoftHSM2 AES CBC wrapping currently has a bug, the IV is not correctly used. Only IV=0 will work --*
    IV="00000000000000000000000000000000"

    echo "======================================================="
    echo " AES 256 CBC Unwrap test"
    echo "======================================================="
    # wrapping AES Key with openssl
    openssl enc -aes-256-cbc -e -K $AES_KEK -iv $IV -in aes.key -out openssl_wrapped.data -nopad
    assert $? "OpenSSL / Failed to AES CBC encrypt AES key"

    if [ "${TOKENTYPE}" == "softhsm" ]; then
        echo "SoftHSM2 currently does not support CKM_AES_CBC unwrapping"
        # SoftHSM does not have the wrapped key already, write it for wrap test
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --write-object aes.key --id $ID_UNWRAPPED --type secrkey --key-type AES:32 \
            --usage-decrypt --extractable --label "aes-stored"
        assert $? "PKCS11 / Failed to write AES key"
    else
        # unwrap key
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m AES-CBC --id $ID_KEK --iv $IV --application-id $ID_UNWRAPPED \
            --key-type AES: --input-file openssl_wrapped.data --extractable --application-label "unwrap-aes-with-aes"
        assert $? "PKCS11 / Failed to AES CBC unwrap AES key"

        # compare keys
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --read-object --type secrkey --id $ID_UNWRAPPED --output-file unwrapped.key
        compare_keys $? aes.key unwrapped.key

        # check if AES key was correctly unwrapped with encryption
        # encrypt with openssl
        echo -n "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > aes_plain.data
        openssl enc -aes-256-cbc -in aes_plain.data -out aes_ciphertext_openssl.data -iv $IV -K $AES_KEY
        assert $? "Fail/Openssl"
        # decrypt with pkcs11-tool
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --encrypt --id $ID_UNWRAPPED -m AES-CBC-PAD --iv $IV \
                --input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data
        assert $? "Fail/pkcs11-tool encrypt"
        cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
        assert $? "Fail, AES-CBC - wrong encrypt"
        rm aes_ciphertext_openssl.data aes_ciphertext_pkcs11.data aes_plain.data
    fi
    echo "======================================================="
    echo " AES 256 CBC Wrap test"
    echo "======================================================="
    # Wrapping AES Key with pkcs11-tool
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m AES-CBC --id $ID_KEK --iv $IV --application-id $ID_UNWRAPPED \
        --output-file pkcs11_wrapped.data
    assert $? "Fail, unable to wrap"

    # Compare wrapped keys
    cmp pkcs11_wrapped.data openssl_wrapped.data >/dev/null 2>/dev/null
    assert $? "Fail, AES-CBC - wrapped key incorrect"

    # clean up
    #$PKCS11_TOOL "${PRIV_ARGS[@]}" --delete-object --type secrkey --id $ID_UNWRAPPED
    #assert $? "PKCS11 / Failed to delete unwrapped AES key"
else
    echo "Not supported"
fi

if [[ "$TOKENTYPE" != "softhsm" ]]; then
    # CKM_AES_CBC_PAD -- SoftHSM2 currently doesn't support CKM_AES_CBC_PAD as a wrapping mechanism --
    IV="000102030405060708090A0B0C0D0E0F"
    echo "======================================================="
    echo " AES 256 CBC PAD Wrap test"
    echo "======================================================="
    # Wrapping AES key
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m AES-CBC-PAD --id $ID_KEK --iv $IV --application-id $ID_UNWRAPPED --output-file pkcs11_wrapped.data
    assert $? "PKCS11 / Failed to AES CBC PAD wrap AES key"
    openssl enc -aes-256-cbc -e -K $AES_KEK -iv $IV -in aes.key -out openssl_wrapped.data
    assert $? "OpenSSL / Failed to AES CBC encrypt AES key"
    cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
    assert $? "AES CBC PAD wrong AES key wrap"
fi

if [[ -n $is_openssl_3 ]]; then
    # CKM_AES_KEY_WRAP
    IV="a6a6a6a6a6a6a6a6"
    ID7="0103"
    echo "======================================================="
    echo "AES-KEY-WRAP Wrap test"
    echo "======================================================="
    # RSA Key
    # --AES-KEY-WRAP is not suitable for asymmetric key wrapping since the length of the encoded private key is likely not aligned to 8 bytes

    # AES Key
    openssl enc -id-aes256-wrap -e -K $AES_KEK -iv $IV -in aes.key -out openssl_wrapped.data
    assert $? "OpenSSL / Failed to AES KEY WRAP wrap AES key"
    
    # Wrapping
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m AES-KEY-WRAP --id $ID_KEK --iv $IV --application-id $ID_UNWRAPPED \
        --output-file pkcs11_wrapped.data
    assert $? "PKCS11 / Failed to AES KEY WRAP wrap AES key"
    cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
    assert $? "AES KEY WRAP wrong AES key wrap"

    echo "======================================================="
    echo "AES-KEY-WRAP Unwrap test"
    echo "======================================================="
    # Unwrapping
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m AES-KEY-WRAP --id $ID_KEK --iv $IV --application-id $ID7 \
        --key-type AES: --input-file openssl_wrapped.data --extractable
    assert $? "PKCS11 / Failed to AES KEY WRAP wrap unwrap AES key"
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --read-object --type secrkey --id $ID7 --output-file unwrapped.key
    compare_keys $? aes.key unwrapped.key
    # Cleanup
    $PKCS11_TOOL "${PRIV_ARGS[@]}" --delete-object --type secrkey --id $ID_UNWRAPPED
    assert $? "PKCS11 / Failed to delete unwrapped AES key"

    if [[ "$TOKENTYPE" != "kryoptic" ]]; then
        echo "======================================================="
        echo "AES-KEY-WRAP-PAD Wrap test"
        echo "======================================================="
        # CKM_AES_KEY_WRAP_PAD
        IV="a65959a6"
        ID8="0104"
        # AES Key
        openssl enc -id-aes256-wrap-pad -e -K $AES_KEK -iv $IV -in aes.key -out openssl_wrapped.data
        assert $? "OpenSSL / Failed to AES KEY WRAP PAD encrypt AES key"
        # Wrapping
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --wrap -m AES-KEY-WRAP-PAD --id $ID_KEK --iv $IV --application-id $ID7 --output-file pkcs11_wrapped.data
        assert $? "PKCS11 / Failed to AES KEY WRAP PAD wrap AES key"
        cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
        assert $? "AES KEY WRAP PAD wrong AES key wrap"

        echo "======================================================="
        echo "AES-KEY-WRAP-PAD Unwrap test"
        echo "======================================================="
        # Unwrapping
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --unwrap -m AES-KEY-WRAP-PAD --id $ID_KEK --iv $IV --application-id $ID8 --key-type AES: --input-file openssl_wrapped.data --extractable
        assert $? "PKCS11 / Failed to AES KEY WRAP PAD wrap unwrap AES key"
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --read-object --type secrkey --id $ID8 --output-file unwrapped.key
        assert $? "PKCS11 / Failed to read unwrapped AES key"
        cmp aes.key unwrapped.key
        assert $? "AES KEY WRAP PAD wrong AES key unwrap"
        # Cleanup
        $PKCS11_TOOL "${PRIV_ARGS[@]}" --delete-object --type secrkey --id $ID8
        assert $? "PKCS11 / Failed to delete unwrapped AES key"
    fi
fi
$PKCS11_TOOL "${PRIV_ARGS[@]}" -O

rm -f aes.key aes_kek.key pkcs11_wrapped.data openssl_wrapped.data unwrapped.key

echo "======================================================="
echo "Cleanup"
echo "======================================================="
token_cleanup

exit $ERRORS
