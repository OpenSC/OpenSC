#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

TOKENTYPE=$1
TOKENTYPE=${TOKENTYPE:-$TEST_PKCS11_BACKEND}

if [ "${TOKENTYPE}" == "" ]; then
    TOKENTYPE=softhsm
    echo "No tokentype provided, running with SoftHSM"
fi

source "$SOURCE_PATH/tests/common.sh" "$TOKENTYPE"

echo "======================================================="
echo "Setup $TOKENTYPE"
echo "======================================================="
if [[ ! -f "$P11LIB" ]]; then
    echo "WARNING: The $TOKENTYPE is not installed. Can not run this test"
    exit 77;
fi

card_setup
assert $? "Failed to set up card"

echo "======================================================="
echo "Test URI without --uri-with-slot-id (default)"
echo "======================================================="
# Test that slot URIs do NOT contain slot-id by default
$PKCS11_TOOL --module "${P11LIB}" -L 2>/dev/null | grep 'uri' | grep 'slot-id' && {
    echo "ERROR: Found slot-id in URI without --uri-with-slot-id flag"
    ERRORS=1
}

# Test that object URIs do NOT contain slot-id by default
$PKCS11_TOOL --module "${P11LIB}" -O 2>/dev/null | grep 'uri:' | grep 'slot-id' && {
    echo "ERROR: Found slot-id in object URI without --uri-with-slot-id flag"
    ERRORS=1
}

echo "======================================================="
echo "Test URI with --uri-with-slot-id flag"
echo "======================================================="
# Test that slot URIs DO contain slot-id with the flag
$PKCS11_TOOL --module "${P11LIB}" --uri-with-slot-id -L 2>/dev/null | grep 'uri' | grep 'slot-id' >/dev/null
assert $? "Expected slot-id in URI with --uri-with-slot-id flag for slots"

# Test that object URIs DO contain slot-id with the flag
$PKCS11_TOOL --module "${P11LIB}" --uri-with-slot-id -O 2>/dev/null | grep 'uri:' | grep 'slot-id' >/dev/null
assert $? "Expected slot-id in URI with --uri-with-slot-id flag for objects"

# Verify the URI format is still valid (contains pkcs11:)
$PKCS11_TOOL --module "${P11LIB}" --uri-with-slot-id -L 2>/dev/null | grep 'uri' | grep 'pkcs11:' >/dev/null
assert $? "URI format validation failed for slots with --uri-with-slot-id"

$PKCS11_TOOL --module "${P11LIB}" --uri-with-slot-id -O 2>/dev/null | grep 'uri:' | grep 'pkcs11:' >/dev/null
assert $? "URI format validation failed for objects with --uri-with-slot-id"

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit "${ERRORS}"
