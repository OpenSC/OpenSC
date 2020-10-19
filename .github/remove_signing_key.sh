#!/bin/sh

set -ex -o xtrace

pushd .github/
security delete-keychain mac-build.keychain
rm -f DeveloperIDApplication.cer DeveloperIDInstaller.cer key.p12
popd
