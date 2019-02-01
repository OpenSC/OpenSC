#!/bin/bash

source common.sh

echo "======================================================="
echo "Setup SoftHSM"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNINIG: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi
card_setup

echo "======================================================="
echo "Test"
echo "======================================================="
$PKCS11_TOOL --test -p $PIN --module $P11LIB
assert $? "Failed running tests"

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit $ERRORS
