#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

echo "Running all supported tests for SoftHSM token..."

$SOURCE_PATH/tests/test-p11test.sh softhsm
$SOURCE_PATH/tests/test-pkcs11-tool-allowed-mechanisms.sh softhsm
$SOURCE_PATH/tests/test-pkcs11-tool-import.sh softhsm
$SOURCE_PATH/tests/test-pkcs11-tool-sign-verify.sh softhsm
$SOURCE_PATH/tests/test-pkcs11-tool-sym-crypt.sh softhsm
$SOURCE_PATH/tests/test-pkcs11-tool-test-threads.sh softhsm
$SOURCE_PATH/tests/test-pkcs11-tool-test.sh softhsm
$SOURCE_PATH/tests/test-pkcs11-tool-unwrap-wrap-test.sh softhsm
