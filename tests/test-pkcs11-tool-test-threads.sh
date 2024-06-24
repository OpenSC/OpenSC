#!/bin/bash

if [ -z "$MESON_BUILD_ROOT" ]; then
	SOURCE_PATH=${SOURCE_PATH:-..}
	BUILD_PATH=${BUILD_PATH:-..}
else
	SOURCE_PATH="$MESON_SOURCE_ROOT"
	BUILD_PATH="$MESON_BUILD_ROOT"
fi

source "$SOURCE_PATH/tests/common.sh"

if [ -z "$MESON_BUILD_ROOT" ]; then
	P11LIB="../src/pkcs11/.libs/opensc-pkcs11.so"
else
	P11LIB="$MESON_BUILD_ROOT/src/pkcs11/libopensc-pkcs11.so"
fi

echo "======================================================="
echo "Test pkcs11 threads IN "
echo "======================================================="
$PKCS11_TOOL --test-threads IN -L --module="$P11LIB"
assert $? "Failed running tests"


echo "======================================================="
echo "Test pkcs11 threads ILGISLT0 "
echo "======================================================="
$PKCS11_TOOL --test-threads ILGISLT0 -L --module="$P11LIB"
assert $? "Failed running tests"

exit $ERRORS
