#!/bin/bash

TOKENTYPE=$1

if [ "${TOKENTYPE}" == "" ]; then
    TOKENTYPE=softhsm
    echo "No tokentype provided, running with SoftHSM"
elif [ "${TOKENTYPE}" != "softhsm" ]; then
    echo "Supported only for softhsm"
    exit 1
fi

if [ -z "$MESON_BUILD_ROOT" ]; then
	SOURCE_PATH=${SOURCE_PATH:-..}
	BUILD_PATH=${BUILD_PATH:-..}
else
	SOURCE_PATH="$MESON_SOURCE_ROOT"
	BUILD_PATH="$MESON_BUILD_ROOT"
fi

source "$SOURCE_PATH/tests/common.sh" $TOKENTYPE

if [ -z "$MESON_BUILD_ROOT" ]; then
	P11LIB="../src/pkcs11/.libs/opensc-pkcs11.so"
	OPENSC_TOOL="../src/tools/opensc-tool"
else
	P11LIB="$MESON_BUILD_ROOT/src/pkcs11/libopensc-pkcs11.so"
	OPENSC_TOOL="$MESON_BUILD_ROOT/src/tools/opensc-tool"
fi

echo "======================================================="
echo "Test pkcs11 threads IN "
echo "======================================================="
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
