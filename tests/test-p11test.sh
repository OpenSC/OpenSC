#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

TOKENTYPE=$1
TOKENTYPE=${TOKENTYPE:-$TEST_PKCS11_BACKEND}

if [ "${TOKENTYPE}" == "softokn" ]; then
	echo "p11test not supported"
	exit 1
elif [ "${TOKENTYPE}" == "" ]; then
    TOKENTYPE=softhsm
    echo "No tokentype provided, running with SoftHSM"
fi

source $SOURCE_PATH/tests/common.sh $TOKENTYPE

echo "======================================================="
echo "Setup $TOKENTYPE"
echo "======================================================="
if [[ ! -f $P11LIB ]]; then
    echo "WARNING: The SoftHSM is not installed. Can not run this test"
    exit 77;
fi

card_setup
assert $? "Failed to set up card"

echo "======================================================="
echo "Run p11test"
echo "======================================================="
$VALGRIND "$BUILD_PATH/src/tests/p11test/p11test" -v -m $P11LIB -o $TOKENTYPE.json -p $PIN
assert $? "Failed running tests"

# Run the input through sed to skip the mechanism part:
#  * broken because of uninitialized memory in softhsm
#  * different for different softhsm versions
function filter_log() {
	sed -n '/readonly_tests/,$p' $1
}

REF_FILE="$BUILD_PATH/tests/${TOKENTYPE}_ref.json"
if [[ "$TOKENTYPE" == "softhsm" ]]; then
	VERSION=$(softhsm2-util --version)
	REF_FILE="$SOURCE_PATH/tests/${TOKENTYPE}_${VERSION}_ref.json"
fi
if [[ -f "/proc/sys/crypto/fips_enabled" && $(cat /proc/sys/crypto/fips_enabled) == "1" ]]; then
	REF_FILE="$SOURCE_PATH/tests/${TOKENTYPE}_fips_ref.json"
fi

echo "Comparing with $REF_FILE"
diff -U5 <(filter_log $REF_FILE) <(filter_log $TOKENTYPE.json)
assert $? "Unexpected results"

echo "======================================================="
echo "Run p11test with PKCS11SPY"
echo "======================================================="
export PKCS11SPY="$P11LIB"
$VALGRIND "$BUILD_PATH/src/tests/p11test/p11test" -v -m "$BUILD_PATH/src/pkcs11/.libs/pkcs11-spy.so" -o $TOKENTYPE.json -p $PIN
assert $? "Failed running tests"

echo "Comparing with $REF_FILE"
diff -U5 <(filter_log $REF_FILE) <(filter_log $TOKENTYPE.json)
assert $? "Unexpected results with PKCS11 spy"

rm $TOKENTYPE.json

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit $ERRORS
