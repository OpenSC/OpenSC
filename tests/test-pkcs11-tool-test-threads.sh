#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-../}

source $SOURCE_PATH/tests/common.sh

echo "======================================================="
echo "Setup SoftHSM"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNINIG: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi

card_setup

echo "======================================================="
echo "Test pkcs11 threads IN "
echo "======================================================="
$PKCS11_TOOL --test-threads IN -L
assert $? "Failed running tests"


echo "======================================================="
echo "Test pkcs11 threads ILGISLT0 "
echo "======================================================="
$PKCS11_TOOL --test-threads ILGISLT0 -L
assert $? "Failed running tests"

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit $ERRORS
