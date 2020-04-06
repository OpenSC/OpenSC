#!/bin/sh

set -ex -o xtrace

pushd .github/
security delete-keychain mac-build.keychain
rm -f certificate.cer certificate.p12
popd
