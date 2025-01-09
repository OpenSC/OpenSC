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
echo "Run p11test"
echo "======================================================="
$VALGRIND ./../src/tests/p11test/p11test -v -m $P11LIB -o softhsm.json -p $PIN
assert $? "Failed running tests"

# Run the input shrough sed to skip the mechanism part:
#  * broken because of uninitialized memory in softhsm
#  * different for different softhsm versions
# and interface tests
#  * different results for softhsm and pkcs11-spy
function filter_log() {
	sed -n '/readonly_tests/,$p' $1
}

REF_FILE="$SOURCE_PATH/tests/softhsm_ref.json"
if [[ -f "/proc/sys/crypto/fips_enabled" && $(cat /proc/sys/crypto/fips_enabled) == "1" ]]; then
	REF_FILE="$SOURCE_PATH/tests/softhsm_fips_ref.json"
fi

diff -U3 <(filter_log $REF_FILE) <(filter_log softhsm.json)
assert $? "Unexpected results"

echo "======================================================="
echo "Run p11test with PKCS11SPY"
echo "======================================================="
export PKCS11SPY="$P11LIB"
$VALGRIND ./../src/tests/p11test/p11test -v -m ../src/pkcs11/.libs/pkcs11-spy.so -o softhsm.json -p $PIN
assert $? "Failed running tests"

diff -U3 <(filter_log $REF_FILE) <(filter_log softhsm.json)
assert $? "Unexpected results with PKCS11 spy"

rm softhsm.json

echo "======================================================="
echo "Cleanup"
echo "======================================================="
card_cleanup

exit $ERRORS
