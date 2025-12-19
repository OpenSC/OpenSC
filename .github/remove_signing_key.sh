#!/bin/sh

set -ex -o xtrace

pushd .github/
security delete-keychain mac-build.keychain
rm -f DeveloperIDApplication.p12 DeveloperIDInstaller.p12
popd
