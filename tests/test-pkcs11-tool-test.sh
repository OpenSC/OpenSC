#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

source $SOURCE_PATH/tests/common.sh

echo "======================================================="
echo "Setup SoftHSM"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNING: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi

# The Ubuntu has old softhsm version not supporting this feature
grep "Ubuntu 18.04" /etc/issue && echo "WARNING: Not supported on Ubuntu 18.04" && exit 77

card_setup
assert $? "Failed to set up card"

echo "======================================================="
echo "Test"
echo "======================================================="
$PKCS11_TOOL --test -p "${PIN}" --module "${P11LIB}"
assert $? "Failed running tests"

echo "======================================================="
echo "Test objects URI"
echo "======================================================="
$PKCS11_TOOL -O 2>/dev/null | grep 'uri:' 2>/dev/null >/dev/null
assert $? "Failed running objects URI tests"
$PKCS11_TOOL -O 2>/dev/null | grep 'uri:' | awk -F 'uri:' '{print $2}' | tr -d ' ' | grep ^"pkcs11:" 2>/dev/null >/dev/null
assert $? "Failed running objects URI tests"

echo "======================================================="
echo "Test slots URI"
echo "======================================================="
$PKCS11_TOOL -L 2>/dev/null | grep 'uri' 2>/dev/null >/dev/null
assert $? "Failed running slots URI tests"
$PKCS11_TOOL -O 2>/dev/null | grep 'uri' | awk -F 'uri*:' '{print $2}' | tr -d ' '  | grep ^"pkcs11:" 2>/dev/null >/dev/null
assert $? "Failed running slots URI tests"

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit "${ERRORS}"
