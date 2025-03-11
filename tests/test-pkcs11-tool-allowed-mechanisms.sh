#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

TOKENTYPE=$1

if [ "${TOKENTYPE}" == "softokn" ]; then
	echo "Generate key-pair with CKA_ALLOWED_MECHANISMS not supported"
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
    echo "WARNING: The $TOKENTYPE is not installed. Can not run this test"
    exit 77;
fi

initialize_token

echo "======================================================="
echo "Generate key-pair with CKA_ALLOWED_MECHANISMS"
echo "======================================================="
ID="05"
MECHANISMS="RSA-PKCS,SHA1-RSA-PKCS,RSA-PKCS-PSS"
# Generate key pair
$PKCS11_TOOL --keypairgen --key-type="RSA:1024" --login --pin=$PIN \
	--module="$P11LIB" --label="test" --id="$ID" \
	--allowed-mechanisms="$MECHANISMS,SHA384-RSA-PKCS"
assert $? "Failed to Generate RSA key pair"

# Check the attributes are visible
$PKCS11_TOOL --list-objects --login --pin=$PIN \
	--module="$P11LIB" --id=$ID > objects.list
assert $? "Failed to list objects"
grep -q "Allowed mechanisms" objects.list
assert $? "Allowed mechanisms not in the object list"
grep -q "$MECHANISMS" objects.list
assert $? "The $MECHANISMS is not in the list"

# Make sure we are not allowed to use forbidden mechanism
echo "data to sign (max 100 bytes)" > data
$PKCS11_TOOL --id $ID -s -p $PIN -m SHA256-RSA-PKCS --module $P11LIB \
       --input-file data --output-file data.sig &> sign.log
grep -q CKR_MECHANISM_INVALID sign.log
assert $? "It was possible to sign using non-allowed mechanism"
rm -f data{,.sig}

echo "======================================================="
echo "Cleanup"
echo "======================================================="
token_cleanup

rm objects.list sign.log

exit $ERRORS
