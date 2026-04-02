#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

echo "Running all supported tests for NSS Softokn token..."

export TEST_PKCS11_BACKEND=softokn
pushd tests
make check \
	TESTS='test-pkcs11-tool-import.sh
	test-pkcs11-tool-sign-verify.sh
	test-pkcs11-tool-unwrap-wrap-test.sh'
RV=$?
popd
if [ $RV -ne 0 ]; then
	./.github/dump-logs.sh
	exit $RV
fi
