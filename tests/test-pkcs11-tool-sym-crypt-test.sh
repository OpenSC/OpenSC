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

echo "======================================================="
echo "Cleanup"
echo "======================================================="
softhsm_cleanup

rm objects.list
rm aes_128.key aes_plain.data aes_plain_test.data aes_ciphertext_openssl.data aes_ciphertext_pkcs11.data aes_plain_pkcs11.data
exit $ERRORS
