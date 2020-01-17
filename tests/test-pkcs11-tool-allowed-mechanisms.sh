#!/bin/bash

source common.sh

echo "======================================================="
echo "Setup SoftHSM"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNINIG: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi
# The Ubuntu has old softhsm version not supporting this feature
grep "Ubuntu 18.04" /etc/issue && echo "WARNING: Not supported on Ubuntu 18.04" && exit 77

softhsm_initialize

echo "======================================================="
echo "Generate key-pair with CKA_ALLOWED_MECHANISMS"
echo "======================================================="
ID="05"
MECHANISMS="RSA-PKCS,SHA1-RSA-PKCS,RSA-PKCS-PSS"
# Generate key pair
$PKCS11_TOOL --keypairgen --key-type="RSA:" --login --pin=$PIN \
	--module="$P11LIB" --label="test" --id="$ID" \
	--allowed-mechanisms="$MECHANISMS"
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
softhsm_cleanup

rm objects.list 

exit $ERRORS
