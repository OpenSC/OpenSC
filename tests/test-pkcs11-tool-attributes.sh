#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

TOKENTYPE=$1
TOKENTYPE=${TOKENTYPE:-$TEST_PKCS11_BACKEND}

if [ "${TOKENTYPE}" == "" ]; then
	TOKENTYPE=softhsm
	echo "No tokentype provided, running with SoftHSM"
fi

source $SOURCE_PATH/tests/common.sh $TOKENTYPE

echo "======================================================="
echo "Setup $TOKENTYPE"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
	echo "WARNING: The $TOKENTYPE is not installed. Can not run this test"
	exit 77;
fi

initialize_token

echo "======================================================="
echo "Generate an AES key"
echo "======================================================="
$PKCS11_TOOL "${PRIV_ARGS[@]}" --keygen --key-type AES:32 --label attr-aes --id 21
assert $? "Failed to generate AES key"

echo "======================================================="
echo "--read-attribute"
echo "======================================================="
$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 21 \
	--read-attribute CKA_LABEL,key_type --read-attribute value_len > attrs.out
assert $? "Failed to read attributes"
cat attrs.out
grep -qx "CKA_LABEL: attr-aes" attrs.out
assert $? "CKA_LABEL not read back"
grep -qx "CKA_KEY_TYPE: CKK_AES" attrs.out
assert $? "CKA_KEY_TYPE not read back"
grep -qx "CKA_VALUE_LEN: 32" attrs.out
assert $? "CKA_VALUE_LEN not read back"

$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 21 --read-attribute no_such_attribute > /dev/null 2>&1
[[ $? != 0 ]]
assert $? "An unknown attribute name was accepted"

$PKCS11_TOOL "${PRIV_ARGS[@]}" --read-attribute CKA_LABEL > /dev/null 2>&1
[[ $? != 0 ]]
assert $? "--read-attribute without an object was accepted"

if [ "${TOKENTYPE}" == "softokn" ]; then
	echo "Setting attributes is not tested with softokn"
else
	echo "======================================================="
	echo "--set-attribute"
	echo "======================================================="
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 21 \
		--set-attribute CKA_LABEL=attr-renamed --set-attribute ID=22
	assert $? "Failed to set CKA_LABEL and CKA_ID"
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 22 --read-attribute label,id > attrs.out
	assert $? "The key is not found under its new CKA_ID"
	cat attrs.out
	grep -qx "CKA_LABEL: attr-renamed" attrs.out
	assert $? "CKA_LABEL was not set"
	grep -qx "CKA_ID: 22" attrs.out
	assert $? "CKA_ID was not set"

	$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 22 --set-attribute CKA_LABEL > /dev/null 2>&1
	[[ $? != 0 ]]
	assert $? "--set-attribute without a value was accepted"

	# What --read-attribute prints is accepted back
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 22 --set-attribute START_DATE=20260102
	assert $? "Failed to set CKA_START_DATE as YYYYMMDD"
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 22 --read-attribute start_date > attrs.out
	assert $? "Failed to read CKA_START_DATE"
	grep -qx "CKA_START_DATE: 2026-01-02" attrs.out
	assert $? "CKA_START_DATE was not set"
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 22 --set-attribute START_DATE=2026-01-03
	assert $? "Failed to set CKA_START_DATE as YYYY-MM-DD"
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 22 --read-attribute start_date > attrs.out
	assert $? "Failed to read CKA_START_DATE"
	grep -qx "CKA_START_DATE: 2026-01-03" attrs.out
	assert $? "CKA_START_DATE was not changed"

	echo "======================================================="
	echo "--set-id still works, and says it is deprecated"
	echo "======================================================="
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 22 --set-id 23 > /dev/null 2> set-id.err
	assert $? "--set-id failed"
	grep -q "deprecated" set-id.err
	assert $? "--set-id did not say it is deprecated"
	$PKCS11_TOOL "${PRIV_ARGS[@]}" --type secrkey --id 23 --read-attribute label > attrs.out
	assert $? "The key is not found under the CKA_ID --set-id gave it"
fi

echo "======================================================="
echo "Cleanup"
echo "======================================================="
token_cleanup

rm -f attrs.out set-id.err

exit $ERRORS
