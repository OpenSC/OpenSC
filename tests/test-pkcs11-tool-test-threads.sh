#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

source $SOURCE_PATH/tests/common.sh

# Test our PKCS #11 module here
P11LIB="../src/pkcs11/.libs/opensc-pkcs11.so"

OPENSC_TOOL="../src/tools/opensc-tool"
echo "check for opensc-tool"
if [[ -f $OPENSC_TOOL ]] ; then
echo "trying opensc-tool -a"
	$OPENSC_TOOL -a
	if [[ "$?" -ne "0" ]] ; then
		echo "No token found, skipping Test pkcs11 threads "
		exit 77
	fi
fi

echo "======================================================="
echo "Test pkcs11 threads IN "
echo "======================================================="
OPENSC_TOOL="../src/tools/opensc-tool"
echo "check for opensc-tool"
if [[ -f $OPENSC_TOOL ]] ; then
echo "trying opensc-tool -a"
	$OPENSC_TOOL -a
	if [[ "$?" -ne "0" ]] ; then
		echo "No token found, skipping Test pkcs11 threads "
		exit 77
	fi
fi

$PKCS11_TOOL --test-threads IN -L --module="$P11LIB"
assert $? "Failed running tests"

echo "======================================================="
echo "Test pkcs11 threads ILGISLT0 "
echo "======================================================="
$PKCS11_TOOL --test-threads ILGISLT0 -L --module="$P11LIB"
assert $? "Failed running tests"

exit $ERRORS
