#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

TOKENTYPE=$1

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

if [ "${TOKENTYPE}" == "softhsm" ]; then
    # The Ubuntu has old softhsm version not supporting this feature
    grep "Ubuntu 18.04" /etc/issue && echo "WARNING: Not supported on Ubuntu 18.04" && exit 77
fi

card_setup
assert $? "Failed to set up card"

echo "======================================================="
echo "Test"
echo "======================================================="
if [ "${TOKENTYPE}" == "softhsm" ]; then
    #SoftHSM only supports CKM_RSA_PKCS_OAEP with --hash-algorithm SHA-1 and --mgf MGF1-SHA1
    # and it accepts pSourceData, but  does not use, so decrypt fails, See pkcs11-tool.c comments
    $PKCS11_TOOL --test -p "${PIN}" --module "${P11LIB}" --hash-algorithm "SHA-1" --mgf "MGF1-SHA1"
    assert $? "Failed running tests"
else
    $PKCS11_TOOL --test -p "${PIN}" --module "${P11LIB}"
    assert $? "Failed running tests"
fi

echo "======================================================="
echo "Test objects URI"
echo "======================================================="
$PKCS11_TOOL --module "${P11LIB}" -O 2>/dev/null | grep 'uri:' 2>/dev/null >/dev/null
assert $? "Failed running objects URI tests"
$PKCS11_TOOL --module "${P11LIB}" -O 2>/dev/null | grep 'uri:' | awk -F 'uri:' '{print $2}' | tr -d ' ' | grep ^"pkcs11:" 2>/dev/null >/dev/null
assert $? "Failed running objects URI tests"

echo "======================================================="
echo "Test slots URI"
echo "======================================================="
$PKCS11_TOOL --module "${P11LIB}" -L 2>/dev/null | grep 'uri' 2>/dev/null >/dev/null
assert $? "Failed running slots URI tests"
$PKCS11_TOOL --module "${P11LIB}" -O 2>/dev/null | grep 'uri' | awk -F 'uri*:' '{print $2}' | tr -d ' '  | grep ^"pkcs11:" 2>/dev/null >/dev/null
assert $? "Failed running slots URI tests"

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit "${ERRORS}"
