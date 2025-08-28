#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

echo "Running all supported tests for NSS Softokn token..."

$SOURCE_PATH/tests/test-pkcs11-tool-sign-verify.sh softokn
$SOURCE_PATH/tests/test-pkcs11-tool-import.sh softokn
$SOURCE_PATH/tests/test-pkcs11-tool-unwrap-wrap-test.sh softokn
