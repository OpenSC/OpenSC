#!/bin/bash
SOURCE_PATH=${SOURCE_PATH:-..}

echo "Running all supported tests for Kryoptic token..."

export TEST_PKCS11_BACKEND=kryoptic
pushd tests
make check \
	TESTS='test-p11test.sh
	test-pkcs11-tool-allowed-mechanisms.sh
	test-pkcs11-tool-import.sh
	test-pkcs11-tool-sign-verify.sh
	test-pkcs11-tool-test.sh
	test-pkcs11-tool-unwrap-wrap-test.sh'
# test-pkcs11-tool-sym-crypt-test.sh # TODO
RV=$?
popd
if [ $RV -ne 0 ]; then
	./.github/dump-logs.sh
	exit $RV
fi
