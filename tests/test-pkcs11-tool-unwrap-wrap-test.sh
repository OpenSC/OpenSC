#!/bin/bash
source common.sh

echo "======================================================="
echo "Setup SoftHSM"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNING: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi
# The Ubuntu has old softhsm version not supporting this feature
grep "Ubuntu 18.04" /etc/issue && echo "WARNING: Not supported on Ubuntu 18.04" && exit 77
softhsm_initialize

PKCS11_TOOL_W_PIN="$PKCS11_TOOL --module $P11LIB --pin $PIN"

echo "======================================================="
echo " RSA-PKCS Unwrap test"
echo "======================================================="
ID1="85"
ID2="95"
ID3="96"
# Generate RSA key (this key is used to unwrap/wrap operation)
$PKCS11_TOOL_W_PIN --keypairgen --key-type rsa:1024 --id $ID1 --usage-wrap
assert $? "Failed to Generate RSA key"
# export public key
$PKCS11_TOOL_W_PIN --read-object --type pubkey --id $ID1 -o rsa_pub.key
assert $? "Failed to export public key"

# create AES key
KEY="70707070707070707070707070707070"

echo -n $KEY|xxd -p -r > aes_plain_key
# wrap AES key
openssl rsautl -encrypt -pubin -keyform der -inkey rsa_pub.key -in aes_plain_key -out aes_wrapped_key
assert $? "Failed wrap AES key"

# unwrap key by pkcs11 interface
$PKCS11_TOOL_W_PIN --unwrap -m RSA-PKCS --id $ID1 -i aes_wrapped_key --key-type GENERIC: \
	--extractable --application-id $ID3 --application-label "unwrap-generic-ex" 2>/dev/null
assert $? "Unwrap failed"
# because key is extractable, there is no problem to compare key value with original key
$PKCS11_TOOL_W_PIN --id $ID3 --read-object --type secrkey --output-file generic_extracted_key
assert $? "unable to read key value"
cmp generic_extracted_key aes_plain_key >/dev/null 2>/dev/null
assert $? "extracted key does not match the input key"

# unwrap AES key, not extractable
$PKCS11_TOOL_W_PIN --unwrap -m RSA-PKCS --id $ID1 -i aes_wrapped_key --key-type AES: \
	--application-id $ID2 --application-label "unwrap-aes" 2>/dev/null
assert $? "Unwrap failed"

# To check if AES key was correctly unwrapped (non extractable), we need to encrypt some data by pkcs11 interface and by openssl
# (with same key). If result is same, key was correctly unwrapped.
VECTOR="00000000000000000000000000000000"
echo -n "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" > aes_plain.data

openssl enc -aes-128-cbc -nopad -in aes_plain.data -out aes_ciphertext_openssl.data -iv $VECTOR -K $KEY
assert $? "Fail/Openssl"

$PKCS11_TOOL_W_PIN --encrypt --id $ID2 -m AES-CBC --iv $VECTOR \
        --input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC - wrong encrypt"

echo "======================================================="
echo " RSA-PKCS Wrap test"
echo "======================================================="

$PKCS11_TOOL_W_PIN --wrap -m RSA-PKCS --id $ID1 --application-id $ID3 --output-file wrapped.key
assert $? "Fail, unable to wrap"
$PKCS11_TOOL_W_PIN --decrypt -m RSA-PKCS --id $ID1 --input-file wrapped.key --output-file plain_wrapped.key
assert $? "Fail, unable to decrypt wrapped key"
cmp plain_wrapped.key aes_plain_key >/dev/null 2>/dev/null
assert $? "wrapped key after decipher does not match the original key"

echo "======================================================="
echo " RSA-PKCS Cleanup"
echo "======================================================="

rm rsa_pub.key aes_plain_key aes_wrapped_key aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data aes_plain.data generic_extracted_key wrapped.key plain_wrapped.key

echo "======================================================="
echo " AES wrap/unwrap"
echo "======================================================="

ID_RSA=$(echo "RSA" | tr -d "\n" | od -An -vtx1 | tr -d " " | tr -d "\n")
ID_AES=$(echo "AES" | tr -d "\n" | od -An -vtx1 | tr -d " " | tr -d "\n")
ID_KEK=$(echo "KEK" | tr -d "\n" | od -An -vtx1 | tr -d " " | tr -d "\n")
ID_UNWRAPPED=$(echo "UW" | tr -d "\n" | od -An -vtx1 | tr -d " " | tr -d "\n")

openssl genpkey -algorithm RSA -out rsa_priv.pem
assert $? "OpenSSL / Failed to generate RSA private key"
openssl pkey -in rsa_priv.pem -pubout -out rsa_pub.pem
assert $? "OpenSSL / Failed to convert RSA private key to public"
openssl pkcs8 -topk8 -inform PEM -outform DER -in rsa_priv.pem -out rsa_priv.der -nocrypt
assert $? "OpenSSL / Failed to PKCS8 encode RSA private key"
$PKCS11_TOOL_W_PIN --write-object rsa_priv.pem --id $ID_RSA --type privkey --usage-sign --extractable
assert $? "PKCS11 / Failed to write RSA private key"
$PKCS11_TOOL_W_PIN --write-object rsa_pub.pem --id $ID_RSA --type pubkey --usage-sign
assert $? "PKCS11 / Failed to write RSA public key"

AES_KEY=$(head /dev/urandom | sha256sum | head -c 64)
echo -n $AES_KEY | xxd -p -r > aes.key
$PKCS11_TOOL_W_PIN --write-object aes.key --id $ID_AES --type secrkey --key-type AES:32 --usage-decrypt --extractable
assert $? "PKCS11 / Failed to write AES key"

AES_KEK=$(head /dev/urandom | sha256sum | head -c 64)
echo -n $AES_KEK | xxd -p -r > aes_kek.key
$PKCS11_TOOL_W_PIN --write-object aes_kek.key --id $ID_KEK --type secrkey --key-type AES:32 --usage-wrap --extractable
assert $? "PKCS11 / Failed to write AES KEK"

is_openssl_3=$(openssl version | grep "OpenSSL 3.")
is_softhsm2_2_6_1=$(softhsm2-util -version | grep "2.6.1")

if [[ -n $is_softhsm2_2_6_1 ]]
then
    # CKM_AES_CBC -- SoftHSM2 AES CBC wrapping currently has a bug, the IV is not correctly used. Only IV=0 will work --*
    IV="00000000000000000000000000000000"

        # RSA key
    # SoftHSM2 does not support wrapping asymmetric keys with AES CBC since the length of the encoded private key is likely not aligned to 16 bytes and SoftHSM2 does not pad the input as intended in the PKCS#11 documentation (PKCS#11 mechanisms v3.0, section 2.10.5)

        # AES Key
    openssl enc -aes-256-cbc -e -K $AES_KEK -iv $IV -in aes.key -out openssl_wrapped.data -nopad
    assert $? "OpenSSL / Failed to AES CBC encrypt AES key"
            # Wrapping
    $PKCS11_TOOL_W_PIN --wrap -m AES-CBC --id $ID_KEK --iv $IV --application-id $ID_AES --output-file pkcs11_wrapped.data
    assert $? "PKCS11 / Failed to AES CBC wrap AES key"
    cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
    assert $? "AES CBC wrong AES key wrap"
            # Unwrapping -- SoftHSM2 currently does not support CKM_AES_CBC unwrapping --
    # $PKCS11_TOOL_W_PIN --unwrap -m AES-CBC --id $ID_KEK --iv $IV --application-id $ID_UNWRAPPED --key-type AES: --input-file openssl_wrapped.data --extractable
    # assert $? "PKCS11 / Failed to AES CBC unwrap AES key"
    # $PKCS11_TOOL_W_PIN --read-object --type secrkey --id $ID_UNWRAPPED --output-file unwrapped.key
    # assert $? "PKCS11 / Failed to read unwrapped AES key"
    # cmp aes.key unwrapped.key
    # assert $? "AES CBC wrong AES key unwrap"
            # Cleanup
    # $PKCS11_TOOL_W_PIN --delete-object --type secrkey --id $ID_UNWRAPPED
    # assert $? "PKCS11 / Failed to delete unwrapped AES key"
fi

# CKM_AES_CBC_PAD -- SoftHSM2 currently doesn't support CKM_AES_CBC_PAD as a wrapping mechanism --
# IV="000102030405060708090A0B0C0D0E0F"

    # RSA key
# $PKCS11_TOOL_W_PIN --wrap -m AES-CBC-PAD --id $ID_KEK --iv $IV --application-id $ID_RSA --output-file pkcs11_wrapped.data
# assert $? "PKCS11 / Failed to AES CBC PAD wrap RSA priv key"
# openssl enc -aes-256-cbc -e -K $AES_KEK -iv $IV -in rsa_priv.der -out openssl_wrapped.data
# assert $? "OpenSSL / Failed to AES CBC encrypt RSA priv key"
# cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
# assert $? "AES CBC PAD wrong RSA key wrap"

    # AES key
# $PKCS11_TOOL_W_PIN --wrap -m AES-CBC-PAD --id $ID_KEK --iv $IV --application-id $ID_AES --output-file pkcs11_wrapped.data
# assert $? "PKCS11 / Failed to AES CBC PAD wrap AES key"
# openssl enc -aes-256-cbc -e -K $AES_KEK -iv $IV -in aes.key -out openssl_wrapped.data
# assert $? "OpenSSL / Failed to AES CBC encrypt AES key"
# cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
# assert $? "AES CBC PAD wrong AES key wrap"


if [[ -n $is_openssl_3 ]]
then
    # CKM_AES_KEY_WRAP
    IV="a6a6a6a6a6a6a6a6"

        # RSA Key
    # --AES-KEY-WRAP is not suitable for asymmetric key wrapping since the length of the encoded private key is likely not aligned to 8 bytes

        # AES Key
    openssl enc -id-aes256-wrap -e -K $AES_KEK -iv $IV -in aes.key -out openssl_wrapped.data
    assert $? "OpenSSL / Failed to AES KEY WRAP wrap AES key"
            # Wrapping
    $PKCS11_TOOL_W_PIN --wrap -m AES-KEY-WRAP --id $ID_KEK --iv $IV --application-id $ID_AES --output-file pkcs11_wrapped.data
    assert $? "PKCS11 / Failed to AES KEY WRAP wrap AES key"
    cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
    assert $? "AES KEY WRAP wrong AES key wrap"
            # Unwrapping
    $PKCS11_TOOL_W_PIN --unwrap -m AES-KEY-WRAP --id $ID_KEK --iv $IV --application-id $ID_UNWRAPPED --key-type AES: --input-file openssl_wrapped.data --extractable
    assert $? "PKCS11 / Failed to AES KEY WRAP wrap unwrap AES key"
    $PKCS11_TOOL_W_PIN --read-object --type secrkey --id $ID_UNWRAPPED --output-file unwrapped.key
    assert $? "PKCS11 / Failed to read unwrapped AES key"
    cmp aes.key unwrapped.key
    assert $? "AES KEY WRAP wrong AES key unwrap"
            # Cleanup
    $PKCS11_TOOL_W_PIN --delete-object --type secrkey --id $ID_UNWRAPPED
    assert $? "PKCS11 / Failed to delete unwrapped AES key"

    # CKM_AES_KEY_WRAP_PAD
    IV="a65959a6"

        # RSA Key -- Fails with the current version of SoftHSM2 --
    # $PKCS11_TOOL_W_PIN --wrap -m AES-KEY-WRAP-PAD --id $ID_KEK --iv $IV --application-id $ID_RSA --output-file pkcs11_wrapped.data
    # assert $? "PKCS11 / Failed to AES KEY WRAP PAD wrap RSA priv key"
    # openssl enc -id-aes256-wrap-pad -e -K $AES_KEK -iv $IV -in rsa_priv.der -out openssl_wrapped.data
    # assert $? "OpenSSL / Failed to AES KEY WRAP PAD encrypt RSA priv key"
    # cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
    # assert $? "AES KEY WRAP PAD wrong RSA key wrap"

        # AES Key
    openssl enc -id-aes256-wrap-pad -e -K $AES_KEK -iv $IV -in aes.key -out openssl_wrapped.data
    assert $? "OpenSSL / Failed to AES KEY WRAP PAD encrypt AES key"
            # Wrapping
    $PKCS11_TOOL_W_PIN --wrap -m AES-KEY-WRAP-PAD --id $ID_KEK --iv $IV --application-id $ID_AES --output-file pkcs11_wrapped.data
    assert $? "PKCS11 / Failed to AES KEY WRAP PAD wrap AES key"
    cmp pkcs11_wrapped.data openssl_wrapped.data 2>&1 >/dev/null
    assert $? "AES KEY WRAP PAD wrong AES key wrap"
            # Unwrapping
    $PKCS11_TOOL_W_PIN --unwrap -m AES-KEY-WRAP-PAD --id $ID_KEK --iv $IV --application-id $ID_UNWRAPPED --key-type AES: --input-file openssl_wrapped.data --extractable
    assert $? "PKCS11 / Failed to AES KEY WRAP PAD wrap unwrap AES key"
    $PKCS11_TOOL_W_PIN --read-object --type secrkey --id $ID_UNWRAPPED --output-file unwrapped.key
    assert $? "PKCS11 / Failed to read unwrapped AES key"
    cmp aes.key unwrapped.key
    assert $? "AES KEY WRAP PAD wrong AES key unwrap"
            # Cleanup
    $PKCS11_TOOL_W_PIN --delete-object --type secrkey --id $ID_UNWRAPPED
    assert $? "PKCS11 / Failed to delete unwrapped AES key"
fi

rm rsa_priv.pem rsa_pub.pem rsa_priv.der aes.key aes_kek.key pkcs11_wrapped.data openssl_wrapped.data unwrapped.key

echo "======================================================="
echo "Cleanup"
echo "======================================================="
softhsm_cleanup

exit $ERRORS
