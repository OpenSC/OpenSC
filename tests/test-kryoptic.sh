#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

echo "Running all supported tests for Kryoptic token..."

$SOURCE_PATH/tests/test-p11test.sh kryoptic
$SOURCE_PATH/tests/test-pkcs11-tool-sign-verify.sh kryoptic
$SOURCE_PATH/tests/test-pkcs11-tool-import.sh kryoptic kryoptic
$SOURCE_PATH/tests/test-pkcs11-tool-allowed-mechanisms.sh kryoptic
$SOURCE_PATH/tests/test-pkcs11-tool-test.sh kryoptic
