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

echo "======================================================="
echo " Unwrap test"
echo "======================================================="
ID1="85"
ID2="95"
ID3="96"
# Generate RSA key (this key is used to unwrap/wrap operation)
$PKCS11_TOOL --module="$P11LIB" --login --pin=$PIN --keypairgen --key-type="rsa:1024" --id "$ID1" --usage-wrap
assert $? "Failed to Generate RSA key"
# export public key
$PKCS11_TOOL --module="$P11LIB" --login --pin=$PIN --read-object --type pubkey --id="$ID1" -o rsa_pub.key
assert $? "Failed to export public key"

# create AES key
KEY="70707070707070707070707070707070"

echo -n $KEY|xxd -p -r > aes_plain_key
# wrap AES key
openssl rsautl -encrypt -pubin -keyform der -inkey rsa_pub.key -in aes_plain_key -out aes_wrapped_key
assert $? "Failed wrap AES key"

# unwrap key by pkcs11 interface
$PKCS11_TOOL --module="$P11LIB" --login --pin=$PIN --unwrap --mechanism RSA-PKCS --id "$ID1" -i aes_wrapped_key --key-type GENERIC: \
	--extractable --application-id "$ID3" --application-label "unwrap-generic-ex" 2>/dev/null
assert $? "Unwrap failed"
# because key is extractable, there is no problem to compare key value with original key
$PKCS11_TOOL --module="$P11LIB" --login --pin=$PIN --id "$ID3" --read-object --type secrkey --output-file generic_extracted_key
assert $? "unable to read key value"
cmp generic_extracted_key aes_plain_key >/dev/null 2>/dev/null
assert $? "extracted key does not match the input key"

# unwrap AES key, not extractable
$PKCS11_TOOL --module="$P11LIB" --login --pin=$PIN --unwrap --mechanism RSA-PKCS --id "$ID1" -i aes_wrapped_key --key-type AES: \
	--application-id "$ID2" --application-label "unwrap-aes" 2>/dev/null
assert $? "Unwrap failed"

# To check if AES key was correctly unwrapped (non extractable), we need to encrypt some data by pkcs11 interface and by openssl
# (with same key). If result is same, key was correctly unwrapped.
VECTOR="00000000000000000000000000000000"
echo -n "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" > aes_plain.data

openssl enc -aes-128-cbc -nopad -in aes_plain.data -out aes_ciphertext_openssl.data -iv "${VECTOR}" -K $KEY
assert $? "Fail/Openssl"

$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --encrypt --id "$ID2" -m AES-CBC --iv "${VECTOR}" \
        --input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC - wrong encrypt"

echo "======================================================="
echo " Wrap test"
echo "======================================================="

$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --wrap --mechanism RSA-PKCS --id "$ID1" --application-id  "$ID3" --output-file wrapped.key
assert $? "Fail, unable to wrap"
$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --decrypt --mechanism RSA-PKCS --id "$ID1" --input-file wrapped.key --output-file plain_wrapped.key
assert $? "Fail, unable to decrypt wrapped key"
cmp plain_wrapped.key aes_plain_key >/dev/null 2>/dev/null
assert $? "wrapped key after decipher does not match the original key"

echo "======================================================="
echo "Cleanup"
echo "======================================================="
softhsm_cleanup

rm rsa_pub.key aes_plain_key aes_wrapped_key aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data aes_plain.data generic_extracted_key wrapped.key plain_wrapped.key

exit $ERRORS
