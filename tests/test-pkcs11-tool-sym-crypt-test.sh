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

#echo "======================================================="
#echo "Generate AES key"
#echo "======================================================="
#ID1="85"
# Generate key
#$PKCS11_TOOL --keygen --key-type="aes:32" --login --pin=$PIN \
#	--module="$P11LIB" --label="gen_aes256" --id="$ID1"
#assert $? "Failed to Generate AES key"

echo "======================================================="
echo "import AES key"
echo "======================================================="
ID2="86"
echo -n "pppppppppppppppp" > aes_128.key
# import key
softhsm2-util --import aes_128.key --aes --token "SC test" --pin "$PIN" --label import_aes_128 --id "$ID2"
assert $? "Fail, unable to import key"

$PKCS11_TOOL --module="$P11LIB" --list-objects -l --pin=$PIN  2>/dev/null |tee > objects.list
assert $? "Failed to list objects"

VECTOR="00000000000000000000000000000000"
echo "======================================================="
echo " AES-CBC-PAD"
echo " OpenSSL encrypt, pkcs11-tool decrypt"
echo " pkcs11-tool encrypt, compare to openssl encrypt"
echo "======================================================="

echo "C_Encrypt"
dd if=/dev/urandom bs=200 count=1 >aes_plain.data 2>/dev/null
$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --encrypt --id "$ID2" -m AES-CBC-PAD --iv "${VECTOR}" \
	--input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
openssl enc -aes-128-cbc -in aes_plain.data -out aes_ciphertext_openssl.data -iv "${VECTOR}" -K "70707070707070707070707070707070"
cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC-PAD (C_Encrypt) - wrong encrypt"
echo "C_Decrypt"
$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --decrypt --id "$ID2" -m AES-CBC-PAD --iv "${VECTOR}" \
	--input-file aes_ciphertext_pkcs11.data --output-file aes_plain_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool decrypt"
cmp aes_plain.data aes_plain_pkcs11.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC-PAD (C_Decrypt) - wrong decrypt"

echo "C_DecryptUpdate"
dd if=/dev/urandom bs=8131 count=3 >aes_plain.data 2>/dev/null
openssl enc -aes-128-cbc -in aes_plain.data -out aes_ciphertext_openssl.data -iv "${VECTOR}" -K "70707070707070707070707070707070"
assert $? "Fail, OpenSSL"
$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --decrypt --id "$ID2" -m AES-CBC-PAD --iv "${VECTOR}" \
	--input-file aes_ciphertext_openssl.data --output-file aes_plain_test.data 2>/dev/null
assert $? "Fail/pkcs11-tool (C_DecryptUpdate) decrypt"
cmp aes_plain.data aes_plain_test.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC-PAD - wrong decrypt"
echo "C_EncryptUpdate"
$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --encrypt --id "$ID2" -m AES-CBC-PAD --iv "${VECTOR}" \
	--input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC-PAD (C_EncryptUpdate) - wrong encrypt"

echo "======================================================="
echo " AES-ECB, AES-CBC - must fail, because the length of   "
echo " the input is not multiple od block size               "
echo "======================================================="
echo -n "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" > aes_plain.data
! $PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --encrypt --id "$ID2" -m AES-ECB --input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail, AES-ECB must not work if the input is not a multiple of the block size"
! $PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --encrypt --id "$ID2" -m AES-CBC --iv "${VECTOR}" \
	--input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail, AES-CBC must not work if the input is not a multiple of the block size"

echo -n "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" > aes_plain.data

echo "======================================================="
echo " AES-ECB"
echo " OpenSSL encrypt, pkcs11-tool decrypt"
echo " pkcs11-tool encrypt, compare to openssl encrypt"
echo "======================================================="

openssl enc -aes-128-ecb -nopad -in aes_plain.data -out aes_ciphertext_openssl.data  -K "70707070707070707070707070707070"
assert $? "Fail/OpenSSL"
$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --decrypt --id "$ID2" -m AES-ECB --input-file aes_ciphertext_openssl.data --output-file aes_plain_test.data 2>/dev/null
assert $? "Fail/pkcs11-tool decrypt"
cmp aes_plain.data aes_plain_test.data >/dev/null 2>/dev/null
assert $? "Fail, AES-ECB - wrong decrypt"

$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --encrypt --id "$ID2" -m AES-ECB --input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
cmp aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
assert $? "Fail, AES-ECB - wrong encrypt"

echo "======================================================="
echo " AES-CBC"
echo " OpenSSL encrypt, pkcs11-tool decrypt"
echo " pkcs11-tool encrypt, compare to openssl encrypt"
echo "======================================================="

openssl enc -aes-128-cbc -nopad -in aes_plain.data -out aes_ciphertext_openssl.data -iv "${VECTOR}" -K "70707070707070707070707070707070"
assert $? "Fail/OpenSSL"
$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --decrypt --id "$ID2" -m AES-CBC --iv "${VECTOR}" \
	--input-file aes_ciphertext_openssl.data --output-file aes_plain_test.data 2>/dev/null
assert $? "Fail/pkcs11-tool decrypt"
cmp aes_plain.data aes_plain_test.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC - wrong decrypt"

$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --encrypt --id "$ID2" -m AES-CBC --iv "${VECTOR}" \
	--input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
cmp  aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC - wrong encrypt"

VECTOR="000102030405060708090a0b0c0d0e0f"
echo "======================================================="
echo " AES-CBC, another IV"
echo " OpenSSL encrypt, pkcs11-tool decrypt"
echo " pkcs11-tool encrypt, compare to openssl encrypt"
echo "======================================================="

openssl enc -aes-128-cbc -nopad -in aes_plain.data -out aes_ciphertext_openssl.data -iv "${VECTOR}" -K "70707070707070707070707070707070"
assert $? "Fail/Openssl"
$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --decrypt --id "$ID2" -m AES-CBC --iv "${VECTOR}" \
	--input-file aes_ciphertext_openssl.data --output-file aes_plain_test.data 2>/dev/null
assert $? "Fail/pkcs11-tool decrypt"
cmp aes_plain.data aes_plain_test.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC - wrong decrypt"

$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --encrypt --id "$ID2" -m AES-CBC --iv "${VECTOR}" \
	--input-file aes_plain.data --output-file aes_ciphertext_pkcs11.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
cmp  aes_ciphertext_pkcs11.data aes_ciphertext_openssl.data >/dev/null 2>/dev/null
assert $? "Fail, AES-CBC - wrong encrypt"

ID3="87"
echo "======================================================="
echo " AES-GCM, compare with test vectors"
echo " plaintext vector, pkcs11-tool encrypt, compare to ciphertext & tag vector"
echo " ciphertext & tag vector, pkcs11-tool decrypt, compare to plaintext vector"
echo "======================================================="
# Command line OpenSSL does not support AES GCM, we have to compare with validated test vectors.
# The test vectors come from https://github.com/google/boringssl/blob/master/crypto/cipher_extra/test/cipher_tests.txt lines 354-360.
KEY="feffe9928665731c6d6a8f9467308308"
IV="cafebabefacedbaddecaf888"
PT="d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
CT="42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
AAD="feedfacedeadbeeffeedfacedeadbeefabaddad2"
TAG="5bc94fbc3221a5db94fae95ae7121a47"

echo -n $KEY | xxd -r -p > gcm_128.key
echo -n $PT | xxd -r -p > gcm_vector_plain.data
echo -n $CT | xxd -r -p > gcm_vector_ct_tag.data
echo -n $TAG | xxd -r -p >> gcm_vector_ct_tag.data

softhsm2-util --import gcm_128.key --aes --token "SC test" --pin "$PIN" --label import_aes_gcm_128 --id "$ID3" >/dev/null
assert $? "Fail, unable to import key"

$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --encrypt --id "$ID3" -m AES-GCM --iv "$IV" --aad "$AAD" \
	--tag-bits-len 128 --input-file gcm_vector_plain.data --output-file gcm_test_ct_tag.data 2>/dev/null
assert $? "Fail/pkcs11-tool encrypt"
cmp gcm_vector_ct_tag.data gcm_test_ct_tag.data >/dev/null 2>&1
assert $? "Fail, AES-GCM - wrong encrypt"

$PKCS11_TOOL --module="$P11LIB" --pin "$PIN" --decrypt --id "$ID3" -m AES-GCM --iv "$IV" --aad "$AAD" \
	--tag-bits-len 128 --input-file gcm_vector_ct_tag.data --output-file gcm_test_plain.data 2>/dev/null
assert $? "Fail/pkcs11-tool decrypt"
cmp gcm_vector_plain.data gcm_test_plain.data >/dev/null 2>&1
assert $? "Fail, AES-GCM - wrong decrypt"

echo "======================================================="
echo "Cleanup"
echo "======================================================="
softhsm_cleanup

rm objects.list
rm aes_128.key aes_plain.data aes_plain_test.data aes_ciphertext_openssl.data aes_ciphertext_pkcs11.data aes_plain_pkcs11.data gcm_128.key gcm_vector_plain.data gcm_test_plain.data gcm_vector_ct_tag.data gcm_test_ct_tag.data
exit $ERRORS
