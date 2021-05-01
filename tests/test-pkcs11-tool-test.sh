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

# The Ubuntu has old softhsm version not supporting this feature
grep "Ubuntu 18.04" /etc/issue && echo "WARNING: Not supported on Ubuntu 18.04" && exit 77

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
